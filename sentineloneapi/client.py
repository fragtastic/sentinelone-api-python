from . import exceptions
import datetime
import requests
import logging
import re
from typing import Dict, List


class Client:

    def __init__(self, username=None, password=None, apitoken=None, url=None):
        self.logger = logging.getLogger(__name__)
        self.username: str = username
        self.password: str = password
        self.apitoken: str = apitoken
        if not ((username and password) or apitoken):
            raise exceptions.InvalidParameters('Either username & password or apitoken must be used.')
        if not url:
            raise exceptions.MissingURL('URL must be provided')
        self.url = url
        #############################################
        self._auth_token: str = None
        self._authtoken_createdAt: datetime.datetime = None
        self._authtoken_expiresAt: datetime.datetime = None

    def authenticate(self):
        if not self._auth_token:
            self.logger.info('Authenticating')
            if self.apitoken:
                self.logger.info('Authenticating with apittoken')
                data, errors = self.LoginByApiToken()
                if not errors:
                    self.logger.info('Successful token authentication')
                    self._auth_token = data[0]['token']
                else:
                    raise exceptions.AuthenticationError(errors)
            else:
                self.logger.critical('Unhandled authentication method')
                raise exceptions.AuthenticationError('Unhandled authentication method.')
            self.logger.info('Authenticated')
        else:
            self.logger.warning('Already authenticated')

    def _headers(self) -> Dict:
        if self._auth_token:
            return {
                'Authorization': f'Token {self._auth_token}',
                'Content-Type': 'application/json',
            }
        else:
            return {
                'Content-Type': 'application/json',
            }

    def api_call(self, method, endpoint, payload=None):
        data = []
        errors = []
        nextCursor = None
        while True:
            r, rj = None, None
            if nextCursor:
                payload['cursor'] = nextCursor
            if method.__name__ == 'post':
                r = method(url=self.url + endpoint, json=payload, headers=self._headers())
            elif method.__name__ == 'get':
                r = method(url=self.url + endpoint, params=payload, headers=self._headers())
            else:
                raise exceptions.UnhandledRequestType(method)
            rj = r.json()
            if isinstance(rj['data'], list):
                data.extend(rj['data'])
            else:
                data.append(rj['data'])
            errors.extend(rj.get('errors', []))
            self.logger.debug(f'{endpoint} > {r.status_code} {r.reason}')
            self.logger.debug(f'{endpoint} > {rj}')
            if r.status_code != 200:
                self.logger.warning(f"{endpoint} > {rj['errors']}")

            nextCursor = rj.get('pagination', {}).get('nextCursor', None)
            if not nextCursor:
                break

        return data, errors


    ##
    # Agents Actions
    ##
    def DecommissionAgent(self, groupIds=None, ids=None, payload=None):
        """
        If a user is scheduled for time off, or a device is scheduled for maintenance, you can decommission the Agent.
        This removes the Agent from the Management Console. When the Agent communicates with the Management again, the
        Management recommissions it and returns it to the Console. Use this command to decommission the Agents that match the filter.
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        403 - User has insufficient permissions to perform the requested action
        :return:
        """
        endpoint = '/web/api/v2.1/agents/actions/decommission'
        if payload is None:
            payload = {"filter": {}}
        if groupIds is not None:
            if isinstance(groupIds, list):
                payload["filter"]["groupIds"] = ",".join(groupIds)
            else:
                payload["filter"]["groupIds"] = groupIds
        if ids is not None:
            if isinstance(ids, list):
                payload["filter"]["ids"] = ",".join(ids)
            else:
                payload["filter"]["ids"] = ids
        return self.api_call(requests.post, endpoint, payload)


    ##
    # Agents
    ##
    def CountAgents(self, payload=None):
        """
        Get the count of Agents that match a filter. This command is useful to run
        before you run other commands. You will be able to manage Agent maintenance better
        if you know how many Agents will get a command that takes time (such as Update Software).
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        """
        endpoint = '/web/api/v2.1/agents/count'
        return self.api_call(requests.get, endpoint, payload)

    def GetAgents(self, siteIds=None, infected=None, networkStatuses=None, payload=None):
        """
        Get the Agents, and their data, that match the filter. This command gives the Agent ID,
        which you can use in other commands.
        To save the list and data to a CSV file, use "export/agents".
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        """
        endpoint = '/web/api/v2.1/agents'
        if payload is None:
            payload = {}
        if siteIds is not None:
            if isinstance(siteIds, list):
                payload["siteIds"] = ",".join(siteIds)
            else:
                payload["siteIds"] = siteIds
        if infected is not None:
            payload["infected"] = infected
        if networkStatuses is not None:
            if isinstance(networkStatuses, list):
                payload["networkStatuses"] = ",".join(networkStatuses)
            else:
                payload["networkStatuses"] = networkStatuses
        return self.api_call(requests.get, endpoint, payload)

    def MoveToSite(self, siteId, computerName, payload=None):
        """
        Move an Agent that matches the filter to a specified site.
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information
        401 - Unauthorized access - please sign in and retry
        403 - User has insufficient permissions to perform the requested action
        :return:
        """
        endpoint = '/web/api/v2.1/agents/actions/move-to-site'
        payload = {
            "data": {
                "targetSiteId": siteId
            },
            "filter": {
                "computerName__like": computerName
            }
        }
        return self.api_call(requests.post, endpoint, payload)


    ##
    # Application Risk
    ##

    def GetCves(self, siteIds=None, payload=None):
        """
        Get known CVEs for applications that are installed on endpoints with Application Risk-enabled Agents.
        Application Risk requires Complete SKU. This feature is in EA. To join the EA program, contact your SentinelOne Sales Rep.
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        """
        endpoint = '/web/api/v2.1/installed-applications/cves'
        if payload is None:
            payload = {}
        if siteIds is not None:
            if isinstance(siteIds, list):
                payload["siteIds"] = ",".join(siteIds)
            else:
                payload["siteIds"] = siteIds
        return self.api_call(requests.get, endpoint, payload)

    ##
    # Groups
    ##

    def GetGroups(self, siteId, payload=None):
        """
        Get data of groups that match the filter.
        Response Messages:
        200 - Success
        400 - Invalid user input received. See error details for further information
        401 - Unauthorized access - please sign in and retry
        """
        endpoint = f'/web/api/v2.1/groups'
        payload = {
            "filter": {
                "siteId": siteId
            }
        }
        return self.api_call(requests.get, endpoint, payload)

    def MoveToGroup(self, groupId, computerName, payload=None):
        """
        Move an Agent that matches the filter to a specified group in the same site.
        Response Messages
        204 - Success
        400 - Invalid user input received. See error details for further information
        401 - Unauthorized access - please sign in and retry
        403 - Insufficient permissions
        409 - Conflict
        :return:
        """
        endpoint = f'/web/api/v2.1/groups/{groupId}/move-agents'
        payload = {
            "filter": {
                "computerName__like": computerName
            }
        }
        return self.api_call(requests.put, endpoint, payload)

    ##
    # Alerts
    ##

    def GetAlerts(self, payload=None):
        """
        Get a list of alerts for a given scope
        Response Messages
        200 - Success
        400 - Invalid user input received, See error details for further information
        401 - Unauthorized access - please sign in and retry
        :return:
        """
        endpoint = '/web/api/v2.1/cloud-detection/alerts'
        return self.api_call(requests.get, endpoint, payload)

    ##
    # Policies
    ##

    def AccountPolicy(self, account_id, payload=None):
        """
        Get the policy for the Account given by ID. To get the ID of an Account, run "accounts". See also: Get Policy.
        Response Messages
        200 - Success
        401 - Unauthorized access - please sign in and retry.
        404 - Policy not found
        :return:
        """
        endpoint = f'/web/api/v2.1/accounts/{account_id}/policy'
        return self.api_call(requests.get, endpoint, payload)

    def GlobalPolicy(self, payload=None):
        """
        Get the Global policy. This is the default policy for your deployment. See also: Get Policy.
        Response Messages
        200 - Success
        401 - Unauthorized access - please sign in and retry.
        404 - Policy not found
        :return:
        """
        endpoint = '/web/api/v2.1/tenant/policy'
        return self.api_call(requests.get, endpoint, payload)

    def GroupPolicy(self, group_id, payload=None):
        """
        Get the policy of the Group given by ID. To get the ID of a Group, run "groups". See also: Get Policy.
        Response Messages
        200 - Success
        401 - Unauthorized access - please sign in and retry.
        404 - Policy not found
        :param group_id:
        :return:
        """
        endpoint = f'/web/api/v2.1/groups/{group_id}/policy'
        return self.api_call(requests.get, endpoint, payload)

    def GroupPolicy(self, site_id, payload=None):
        """
        Get the policy of the Site given by ID. To get the ID of a Site, run "sites". See also: Get Policy.
        Response Messages
        200 - Success
        401 - Unauthorized access - please sign in and retry.
        404 - Policy not found
        :param site_id:
        :return:
        """
        endpoint = f'/web/api/v2.1/sites/{site_id}/policy'
        return self.api_call(requests.get, endpoint, payload)

    ##
    # RBAC
    ##

    def GetAllRoles(self, payload=None):
        """
        See roles assigned to users that match the filter, a basic description of the roles, and the number of users for each role.
        Role-Based Access Control (RBAC) has predefined roles. (Currently, customized roles are not supported.), This command gives the ID of the role, which you can use in other commands.
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        :return:
        """
        endpoint = '/web/api/v2.1/rbac/roles'
        return self.api_call(requests.get, endpoint, payload)

    def GetSpecificRoleDefinition(self, role_id, payload=None):
        """
        With the ID of a role (see Get All Roles) you can see the permissions of that role.
        The definition of a role can change in different scopes and SKUs. For example, an Admin role with the scope access of a Site does not have Ranger permissions, but an IT role with the scope access of an Account with a Ranger license does have permissions on Ranger.
        The Response shows role permissions to see views in the WebUI and to use Console features.
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        :param role_id:
        :return:
        """
        endpoint = f'/web/api/v2.1/rbac/role/{role_id}'
        return self.api_call(requests.get, endpoint, payload)

    ##
    # Sites
    ##

    def GetSiteById(self, site_id, payload=None):
        """
        Get the data of the Site of the ID. To get the ID, run "sites".
        The response shows the Site expiration date, SKU, licenses (total and active), token, Account name and ID, who and when it was created and changed, and its status.
        Response Messages
        200 - Success
        401 - Unauthorized access - please sign in and retry.
        404 - Site not found
        :param site_id:
        :return:
        """
        endpoint = f'/web/api/v2.1/sites/{site_id}'
        return self.api_call(requests.get, endpoint, payload)

    def GetSites(self, payload=None):
        """
        Get the Sites that match the filters.
        The response includes the IDs of Sites, which you can use in other commands.
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        :return:
        """
        endpoint = '/web/api/v2.1/sites'
        return self.api_call(requests.get, endpoint, payload)

    ##
    # Updates
    ##

    def DownloadPackage(self, site_id, package_id, payload=None):
        """
        Download a package by site_id ("sites") and filename.
        Rate limit: 2 call per minute for each user token.
        Use this command to manually deploy Agent updates that cannot be deployed with the update-software command (see Agent Actions > Update Software) or through the Console.
        Response Messages
        200 - Success
        401 - Unauthorized access - please sign in and retry.
        404 - Package not found or bad site
        :return:
        """
        endpoint = f'/web/api/v2.1/update/agent/download/{site_id}/{package_id}'
        # return self.api_call(requests.get, endpoint)
        r = requests.get(self.url + endpoint, headers=self._headers())

        self.logger.debug(r.headers)
        d = r.headers['content-disposition']
        fname = re.findall("filename=\"(.+)\"", d)[0]
        with open(fname, 'wb') as f:
            self.logger.info(f'Saving {fname}')
            f.write(r.content)

        return r

    def GetLatestPackages(self, payload=None):
        """
        Get the Agent packages that are uploaded to your Management.
        The response shows the data of each package, including the IDs, which you can use in other commands.
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        :return:
        """
        endpoint = '/web/api/v2.1/update/agent/packages'
        return self.api_call(requests.get, endpoint, payload)

    ##
    # Users
    ##

    def ApiTokenByUserId(self, user_id, payload=None):
        """
        Get the details of the API token generated for a given user.
        Response Messages
        200 - Success
        401 - Unauthorized access - please sign in and retry.
        403 - Insufficient permissions
        404 - User not found
        :param user_id:
        :return:
        """
        endpoint = f'/web/api/v2.1/users/{user_id}/api-token-details'
        return self.api_call(requests.get, endpoint, payload)

    def ApiTokenDetails(self, apitoken=None):
        """
        Get details of the API token that matches the filter.
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information.
        :param apitoken:
        :return:
        """
        endpoint = '/web/api/v2.1/users/api-token-details'
        payload = {
          'data': {
            'apiToken': self.apitoken if not apitoken else apitoken
          }
        }
        return self.api_call(requests.post, endpoint, payload=payload)

    def AuthApp(self, payload=None):
        """
        Authenticate a user with a third-party app, such as DUO or Google Authenticator, for deployments that require Two Factor Authentication.
        Response Messages
        200 - Authenticated
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        :return:
        """
        endpoint = '/web/api/v2.1/users/auth/app'
        return self.api_call(requests.post, endpoint, payload)

    def AuthBySSO(self, scope_id, payload=None):
        """
        Authenticate a Single Sign-On response over SAML v2 protocol.
        Response Messages
        302 - SSO authenticated.
        401 - Not authenticated user.
        404 - Site not found.
        :return:
        """
        endpoint = f'/web/api/v2.1/users/login/sso-saml2/{scope_id}'
        return self.api_call(requests.post, endpoint, payload)

    def AuthRecoveryCode(self, payload=None):
        """
        Authenticate a user with a recovery code.
        Response Messages
        200 - User authenticated.
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        :return:
        """
        endpoint = '/web/api/v2.1/users/auth/recovery-code'
        return self.api_call(requests.post, endpoint, payload)

    def ChangePassword(self, userid: str, currentPassword: str, newPassword: str):
        """
        Change the user password.
        Response Messages
        200 - Password changed
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        403 - Insufficient permissions
        404 - User not found
        :param currentPassword:
        :param currentPassword:
        :param newPassword:
        :return:
        """
        payload = {
            "data": {
                "newPassword": newPassword,
                "currentPassword": currentPassword,
                "confirmNewPassword": newPassword,
                "id": userid
            }
        }
        endpoint = '/web/api/v2.1/users/change-password'
        return self.api_call(requests.post, endpoint, payload=payload)

    def ListUsers(self, payload=None):
        """
        Get a list of users.
        Response Messages
        200 - List of users retrieved successfully.
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry. 
        """
        endpoint = '/web/api/v2.1/users'
        return self.api_call(requests.get, endpoint, payload=payload)

    def Login(self):
        endpoint = '/web/api/v2.1/users/login'

    def LoginByApiToken(self):
        """
        Log in to the API with a token. To learn more about temporary and 6-month tokens and how to generate them, see https://support.sentinelone.com/hc/en-us/articles/360004195934.
        Response Messages
        200 - user logged in
        400 - Invalid user input received. See error details for further information.
        401 - User authentication failed
        :return:
        """
        endpoint = '/web/api/v2.1/users/login/by-api-token'
        payload = {
          'data': {
            'apiToken': self.apitoken
          }
        }
        return self.api_call(requests.post, endpoint, payload=payload)

    def LoginByToken(self):
        """
        Log in with user token.
        Response Messages
        200 - user logged in
        400 - Invalid user input received. See error details for further information.
        401 - User authentication failed
        :return:
        """
        endpoint = '/web/api/v2.1/users/login/by-token'
        raise NotImplementedError
        return self.api_call(requests.get, endpoint)

    def Logout(self, payload):
        """
        Log out the authenticated user.
        Response Messages
        200 - User logged out successfully.
        401 - Unauthorized access - please sign in and retry.
        :return:
        """
        endpoint = '/web/api/v2.1/users/logout'
        return self.api_call(requests.post, endpoint, payload)

    def GenerateApiToken(self, payload=None):
        """
        Get the API token for the authenticated user.
        Response Messages
        200 - API token delivered to user
        401 - Unauthorized access - please sign in and retry.
        :return:
        """
        endpoint = '/web/api/v2.1/users/generate-api-token'
        data, errors = self.api_call(requests.post, endpoint, payload=None)
        # apitoken MUST be set again for subsequent calls to look at token data
        self.apitoken = data['data']['token']
        return data, errors

    def RevokeApiToken(self, userid, payload=None):
        """
        Revoke an API token.
        Response Messages
        200 - Api token revoked
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        403 - Insufficient permissions
        404 - User not found
        :param userid:
        :return:
        """
        endpoint = '/web/api/v2.1/users/revoke-api-token'
        payload = {
          'data': {
            'id': userid
          }
        }
        return self.api_call(requests.post, endpoint, payload=payload)

    def SendVerificationEmail(self, payload=None):
        """
        Send verification email to users that match the filter. Warning: Active users will be locked out of the Management Console until they verify their email. If your Management Console has Onboarding enabled, when you create a new user, the user gets an email invitation. If the user does not respond in time or loses the email, you can send it again. You can send the email invitation to multiple users. Your SMTP server must be correctly configured in Settings > SMTP for the Global scope. Changing the Global SMTP settings requires an Admin role with Global scope or Support.
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        403 - Insufficient permissions
        :return:
        """
        endpoint = '/web/api/v2.1/users/onboarding/send-verification-email'
        payload = {
          "filter": {
            "firstLogin": "2018-02-27T04:49:26.257525Z",
            "email": "admin@sentinelone.com",
            "source": "mgmt",
            "emailVerified": "boolean",
            "fullNameReadOnly": "boolean",
            "twoFaEnabled": "boolean",
            "lastLogin": "2018-02-27T04:49:26.257525Z",
            "ids": [
              {}
            ],
            "allowRemoteShell": "boolean",
            "query": "string",
            "primaryTwoFaMethod": "string",
            "emailReadOnly": "boolean",
            "dateJoined": "2018-02-27T04:49:26.257525Z",
            "groupsReadOnly": "boolean",
            "fullName": "string"
          },
          "data": {}
        }
        raise NotImplementedError
        return self.api_call(requests.post, endpoint, payload)

    def UserByToken(self, accountIds: List[str], groupIds: List[str], siteIds: List[str], tenant: bool, payload=None):
        """
        Get a user by token.
        Response Messages
        200 - User retrieved correctly.
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        :param accountIds:
        :param groupIds:
        :param siteIds:
        :param tenant:
        :return:
        """
        endpoint = '/web/api/v2.1/user'
        raise NotImplementedError
        return self.api_call(requests.get, endpoint, payload)

    ##
    # System
    ##

    def CacheStatus(self, payload=None):
        """
        Get an indication of the system's cache health status.
        This command returns a positive response when the cache server is up and running.
        This command does not require authentication.
        Rate limit: 1 call per second for each IP address that communicates with the Console.
        NOTE - Does not require authentication.
        Response Messages
        200 - Success
        :return:
        """
        endpoint = '/web/api/v2.1/system/status/cache'
        return self.api_call(requests.get, endpoint, payload)

    def DatabaseStatus(self, payload=None):
        """
        Get an indication of the system's database health status.
        This command returns a positive response when the DB server is up and running.
        This command does not require authentication.
        Rate limit: 1 call per second for each IP address that communicates with the Console.
        NOTE - Does not require authentication.
        Response Messages
        200 - Success
        :return:
        """
        endpoint = '/web/api/v2.1/system/status/db'
        return self.api_call(requests.get, endpoint, payload)

    def GetSystemConfig(self, payload=None):
        """
        Get the configuration of your SentinelOne system.
        The response shows basic information of the deployed SKUs and licenses, 2FA, and the Management URL.
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        403 - User does not have required permissions (undocumented)
        :return:
        """
        endpoint = '/web/api/v2.1/system/configuration'
        return self.api_call(requests.get, endpoint, payload)

    def SetSystemConfig(self, payload=None):
        """
        Change the system configuration.
        Before you run this, see Get System Config.
        This command requires a Global Admin user or Support.
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        403 - Insufficient permissions
        :return:
        """
        endpoint = '/web/api/v2.1/system/configuration'
        raise NotImplementedError
        return self.api_call(requests.put, endpoint, payload)

    def SystemInfo(self, payload=None):
        """
        Get the Console build, version, patch, and release information.
        Response Messages
        200 - Success
        401 - Unauthorized access - please sign in and retry.
        :return:
        """
        endpoint = '/web/api/v2.1/system/info'
        return self.api_call(requests.get, endpoint, payload)

    def SystemStatus(self, payload=None):
        """
        Get an indication of the system's health status.
        This command returns a positive response when the Management Console and API server are up and running. This command does not require authentication.
        Rate limit: 1 call per second for each IP address that communicates with the Console.
        NOTE - Does not require authentication
        Response Messages
        200 - Success
        :return:
        """
        endpoint = '/web/api/v2.1/system/status'
        return self.api_call(requests.get, endpoint, payload)



    ##
    # Threats
    ##
    def GetThreads(self, incidentStatuses=None, incidentStatusesNin=None, payload=None):
        """
        Get data of threats that match the filter.
        Response Messages
        200 - Success
        400 - Invalid user input received. See error details for further information.
        401 - Unauthorized access - please sign in and retry.
        """
        endpoint = '/web/api/v2.1/threats'
        if payload is None:
            payload = {}
        if incidentStatuses is not None:
            payload["incidentStatuses"] = incidentStatuses
        if incidentStatusesNin is not None:
            payload["incidentStatusesNin"] = incidentStatusesNin
        return self.api_call(requests.get, endpoint, payload)
