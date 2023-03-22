import { handlePermissionsRequest } from './handlers/permissions-request.js';
import { handlePermissionsGrant } from './handlers/permissions-grant.js';
import { PermissionsRequest } from './messages/permissions-request.js';
import { PermissionsGrant } from './messages/permissions-grant.js';

export const PermissionsInterface = {
  methodHandlers : { 'PermissionsRequest': handlePermissionsRequest, 'PermissionsGrant': handlePermissionsGrant },
  messages       : [ PermissionsRequest, PermissionsGrant ]
};