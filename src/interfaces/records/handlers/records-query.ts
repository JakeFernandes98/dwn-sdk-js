import type { MethodHandler } from '../../types.js';
import type { RecordsQueryMessage, RecordsWriteMessage } from '../types.js';

import { authenticate } from '../../../core/auth.js';
import { BaseMessage } from '../../../core/types.js';
import { DwnMethodName } from '../../../core/message.js';
import { lexicographicalCompare } from '../../../utils/string.js';
import { MessageReply } from '../../../core/message-reply.js';
import { MessageStore } from '../../../store/message-store.js';
import { removeUndefinedProperties } from '../../../utils/object.js';
import { DateSort, RecordsQuery } from '../messages/records-query.js';

export const handleRecordsQuery: MethodHandler = async (
  message,
  messageStore,
  didResolver
): Promise<MessageReply> => {
  let recordsQuery: RecordsQuery;
  try {
    recordsQuery = await RecordsQuery.parse(message as RecordsQueryMessage);
  } catch (e) {
    return new MessageReply({
      status: { code: 400, detail: e.message }
    });
  }

  let replies;
  try {
    await authenticate(message.authorization, didResolver);
    // // console.log("Authenticated")
    await recordsQuery.authorize();
    // // console.log("Authorized")
  } catch (e) {
      return new MessageReply({
        status: { code: 401, detail: e.message }
      });
  }

  let records: BaseMessage[] = []

  if (recordsQuery.author === recordsQuery.target) {
    // console.log('OWNER')
    records = [...records, ...(await fetchRecordsAsOwner(recordsQuery, messageStore))];
  } else {
    // console.log('NON OWNER')

    replies = await fetchGranted(recordsQuery, messageStore)
    // console.log("Replies are ",replies, "With length ", replies.length)
    if(replies.length > 0){
      for(let i = 0; i<replies.length; i++){
        if(replies[i].descriptor.grantedTo == recordsQuery.author && replies[i].descriptor.grantedBy == recordsQuery.target){
          records = [...records, ...(await fetchRecordsAsNonOwner(recordsQuery, messageStore))];
          break
        }
      }
    }
    
    
  }

  // sort if `dataSort` is specified
  if (recordsQuery.message.descriptor.dateSort) {
    records = await sortRecords(records, recordsQuery.message.descriptor.dateSort);
  }

  // strip away `authorization` property for each record before responding
  const entries = [];
  for (const record of records) {
    const recordDuplicate = { ...record };
    delete recordDuplicate.authorization;
    entries.push(recordDuplicate);
  }

  return new MessageReply({
    status: { code: 200, detail: 'OK' },
    entries
  });
};

async function fetchGranted(recordsQuery, messageStore)
: Promise<BaseMessage[]> {

  // console.log(recordsQuery.descriptor)

const includeCriteria = {
  grantedBy: recordsQuery.target,
  grantedTo: recordsQuery.author,
  method: DwnMethodName.PermissionsGrant,
  scope: {
    method: recordsQuery.message.descriptor.method,
    schema: recordsQuery.message.descriptor.filter.schema
  }
};
// console.log("includeCriteria")
// console.log(includeCriteria)
removeUndefinedProperties(includeCriteria);

const granted = await messageStore.query(includeCriteria);
return granted;
}

/**
 * Fetches the records as the owner of the DWN with no additional filtering.
 */
async function fetchRecordsAsOwner(recordsQuery: RecordsQuery, messageStore: MessageStore): Promise<BaseMessage[]> {
  // fetch all published records matching the query
  const includeCriteria = {
    target            : recordsQuery.target,
    method            : DwnMethodName.RecordsWrite,
    isLatestBaseState : 'true',
    ...recordsQuery.message.descriptor.filter
  };
  removeUndefinedProperties(includeCriteria);

  // console.log('Include Criteria')
  // console.log(includeCriteria)

  const records = await messageStore.query(includeCriteria);
  return records;
}

/**
 * Fetches the records as a non-owner, return only:
 * 1. published records; and
 * 2. unpublished records intended for the requester (where `recipient` is the requester)
 */
async function fetchRecordsAsNonOwner(recordsQuery: RecordsQuery, messageStore: MessageStore)
  : Promise<BaseMessage[]> {
  const publishedRecords = await fetchPublishedRecords(recordsQuery, messageStore);
  const unpublishedRecordsForRequester = await fetchUnpublishedRecordsForRequester(recordsQuery, messageStore);
  const unpublishedRecordsByRequester = await fetchUnpublishedRecordsByRequester(recordsQuery, messageStore);
  const records = [...publishedRecords, ...unpublishedRecordsForRequester, ...unpublishedRecordsByRequester];
  return records;
}

/**
 * Fetches only published records.
 */
async function fetchPublishedRecords(recordsQuery: RecordsQuery, messageStore: MessageStore): Promise<BaseMessage[]> {
  // fetch all published records matching the query
  const includeCriteria = {
    target            : recordsQuery.target,
    method            : DwnMethodName.RecordsWrite,
    // published         : 'true',
    isLatestBaseState : 'true',
    ...recordsQuery.message.descriptor.filter
  };
  removeUndefinedProperties(includeCriteria);
  const publishedRecords = await messageStore.query(includeCriteria);
  return publishedRecords;
}

/**
 * Fetches only unpublished records that are intended for the requester (where `recipient` is the requester).
 */
async function fetchUnpublishedRecordsForRequester(recordsQuery: RecordsQuery, messageStore: MessageStore)
  : Promise<BaseMessage[]> {
  // include records where recipient is requester
  const includeCriteria = {
    target            : recordsQuery.target,
    recipient         : recordsQuery.author,
    method            : DwnMethodName.RecordsWrite,
    isLatestBaseState : 'true',
    // published         : 'false',
    ...recordsQuery.message.descriptor.filter
  };
  removeUndefinedProperties(includeCriteria);

  const unpublishedRecordsForRequester = await messageStore.query(includeCriteria);
  return unpublishedRecordsForRequester;
}

/**
 * Fetches only unpublished records that are authored by the requester.
 */
async function fetchUnpublishedRecordsByRequester(recordsQuery: RecordsQuery, messageStore: MessageStore)
  : Promise<BaseMessage[]> {
  // include records where recipient is requester
  const includeCriteria = {
    target            : recordsQuery.target,
    author            : recordsQuery.author,
    method            : DwnMethodName.RecordsWrite,
    isLatestBaseState : 'true',
    // published         : 'false',
    ...recordsQuery.message.descriptor.filter
  };
  removeUndefinedProperties(includeCriteria);

  const unpublishedRecordsForRequester = await messageStore.query(includeCriteria);
  return unpublishedRecordsForRequester;
}

/**
 * Sorts the given records. There are 4 options for dateSort:
 * 1. createdAscending - Sort in ascending order based on when the message was created
 * 2. createdDescending - Sort in descending order based on when the message was created
 * 3. publishedAscending - If the message is published, sort in asc based on publish date
 * 4. publishedDescending - If the message is published, sort in desc based on publish date
 *
 * If sorting is based on date published, records that are not published are filtered out.
 * @param entries - Entries to be sorted if dateSort is present
 * @param dateSort - Sorting scheme
 * @returns Sorted Messages
 */
async function sortRecords(
  entries: BaseMessage[],
  dateSort: DateSort
): Promise<BaseMessage[]> {

  const messages = entries as RecordsWriteMessage[];

  switch (dateSort) {
  case DateSort.CreatedAscending:
    return messages.sort((a, b) => lexicographicalCompare(a.descriptor.dateCreated, b.descriptor.dateCreated));
  case DateSort.CreatedDescending:
    return messages.sort((a, b) => lexicographicalCompare(b.descriptor.dateCreated, a.descriptor.dateCreated));
  case DateSort.PublishedAscending:
    return messages
      .filter(m => m.descriptor.published)
      .sort((a, b) => lexicographicalCompare(a.descriptor.datePublished, b.descriptor.datePublished));
  case DateSort.PublishedDescending:
    return messages
      .filter(m => m.descriptor.published)
      .sort((a, b) => lexicographicalCompare(b.descriptor.datePublished, a.descriptor.datePublished));
  }
}
