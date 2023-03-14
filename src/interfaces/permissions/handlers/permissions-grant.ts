import type { MethodHandler } from '../../types.js';
import type { PermissionsGrantMessage } from '../types.js';

import { canonicalAuth } from '../../../core/auth.js';
import { MessageReply } from '../../../core/message-reply.js';
import { PermissionsGrant } from '../messages/permissions-grant.js';

export const handlePermissionsGrant: MethodHandler = async (
  message,
  messageStore,
  didResolver
): Promise<MessageReply> => {
  const permissionGrant = await PermissionsGrant.parse(message as PermissionsGrantMessage);
  const { author, target } = permissionGrant;

  if (permissionGrant.target !== permissionGrant.grantedBy && permissionGrant.target !== permissionGrant.grantedTo) {
    return new MessageReply({
      status: { code: 400, detail: 'grantedBy or grantedTo must be the targeted message recipient' }
    });
  }

  await canonicalAuth(permissionGrant, didResolver);

  if (author !== permissionGrant.grantedTo) {
    throw new Error('grantee must be signer');
  }

  const index = { author, target, ... message.descriptor };
  await messageStore.put(message, index);

  return new MessageReply({
    status: { code: 202, detail: 'Accepted' }
  });
};