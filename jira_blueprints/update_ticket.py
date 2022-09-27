import argparse
import sys
import requests
from requests.auth import HTTPBasicAuth
import shipyard_utils as shipyard
try:
    import exit_codes
except BaseException:
    from . import exit_codes


# create Artifacts folder paths
base_folder_name = shipyard.logs.determine_base_artifact_folder('jira')
artifact_subfolder_paths = shipyard.logs.determine_artifact_subfolders(
    base_folder_name)
shipyard.logs.create_artifacts_folders(artifact_subfolder_paths)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--jira-url', dest='jira_url', required=True)
    parser.add_argument('--project-key', dest='project_key', required=True)
    parser.add_argument('--username', dest='username', required=True)
    parser.add_argument('--access-token', dest='access_token', required=True)
    parser.add_argument('--ticket-key', dest='ticket_key', required=True)
    parser.add_argument('--summary', dest='summary', required=False)
    parser.add_argument('--description', dest='description', required=False)
    parser.add_argument('--issue-type', dest='issue_type', required=False)
    parser.add_argument('--assignee', dest='assignee', required=False)
    parser.add_argument('--custom-json', dest='custom_json', required=False)
    parser.add_argument(
        '--source-file-name',
        dest='source_file_name',
        required=False)
    parser.add_argument(
        '--source-folder-name',
        dest='source_folder_name',
        default='',
        required=False)
    parser.add_argument('--source-file-name-match-type',
                        dest='source_file_name_match_type',
                        choices={'exact_match', 'regex_match'},
                        default='exact_match',
                        required=False)
    args = parser.parse_args()
    return args


def generate_payload_with_custom(project_key, summary, 
                     description, issue_type, custom_fields=None, assignee_user_id=None):
    """ Generates a JIRA Ticket json payload as well as adds custom fields
    to the payload if any are present.
    see: https://developer.atlassian.com/server/jira/platform
                /jira-rest-api-examples/#editing-an-issue-examples
    for an example of a basic payload.
    """
    
    payload = {
        "fields" : {}
    }
    if summary:
        payload['fields']['summary'] = summary
    if description:
        payload['fields']['description'] = description
    if project_key:
        payload['fields']['project']['key'] = project_key
    if assignee_user_id:
        # add assign json to payload if exists
        assign_data = {
            "assignee": {
                "id": assignee_user_id
            }
        }
        payload["fields"].update(assign_data)
    if custom_fields:
        # add custom fields to the update fields payload
        payload['fields'].update(custom_fields)
    return payload


def get_all_users(username, token, jira_url):
    """ Returns a list of all Jira users."""

    # TODO: Make this loop through pages so the response isn't too large.
    users_endpoint = f"https://{jira_url}/rest/api/2/users/?maxResults=1000"
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.get(users_endpoint,
                            headers=headers,
                            auth=HTTPBasicAuth(username, token)
                            )
    users = response.json()
    return users


def find_user_id(users_response, assignee):

    assignee_user_id = None
    for user in users_response:
        if user['displayName'] == assignee:
            assignee_user_id = user['accountId']
            break
    if not assignee_user_id:
        print(
            f'Assignee {assignee} could not be found. Using project default assignee.')
    return assignee_user_id


def attach_file_to_ticket(username, token, jira_url, issue_key, file_path):
    """ Attaches files to a Jira ticket."""

    attachment_endpoint = f"https://{jira_url}/rest/api/2/issue/{issue_key}/attachments"
    headers = {
        "Accept": "application/json",
        "X-Atlassian-Token": "no-check"
    }

    file_payload = {
        "file": (file_path, open(file_path, "rb"), "application-type")
    }
    response = requests.post(attachment_endpoint,
                             headers=headers,
                             auth=HTTPBasicAuth(username, token),
                             files=file_payload)

    if response.status_code == 200:
        print(f'{file_path} was successfully attached to {issue_key}')
    return response


def update_existing_ticket(username, token, jira_url, ticket_key, payload):
    """ Triggers the Create Issue API and adds a new ticket onto JIRA"""
    
    update_ticket_endpoint = f"https://{jira_url}/rest/api/2/issue/{ticket_key}"
    headers = {
      'Content-Type': 'application/json'
    }

    response = requests.put(update_ticket_endpoint, 
                             headers=headers, 
                             json=payload, 
                             auth=HTTPBasicAuth(username, token)
                             )
    
    if response.status_code == requests.codes.ok:
        print(f"Ticket {ticket_key} created updated")
        return
        
    elif response.status_code == 401: # Permissions Error
        print("You do not have the required permissions to create an issue in ",
              "this project")
        sys.exit(exit_codes.INVALID_CREDENTIALS)

    elif response.status_code == 400: # Bad Request
        print("JIRA responded with Bad Request Error. ",
              f"Response message: {response.text}")
        sys.exit(exit_codes.BAD_REQUEST)

    else: # Some other error
        print("an Unknown Error has occured when attempting your request:",
              f"{response.text}")
        sys.exit(exit_codes.UNKNOWN_ERROR)
    

def main():
    args = get_args()
    username = args.username
    access_token = args.access_token
    project_key = args.project_key
    jira_url = args.jira_url
    additional_fields = args.additional_fields
    summary = args.summary
    description = args.description
    issue_type = args.issue_type
    ticket_key = args.ticket_key
    assignee = args.assignee
    source_file_name = args.source_file_name
    source_folder_name = args.source_folder_name
    source_file_name_match_type = args.source_file_name_match_type

    if assignee:
        users = get_all_users(username, access_token, jira_url)
        assignee_user_id = find_user_id(users, assignee)
    else:
        assignee_user_id = None
    # generate payload
    payload = generate_payload_with_custom(project_key, summary, 
                                description, issue_type, 
                                custom_fields=additional_fields, 
                                assignee_user_id=assignee_user_id)

    update_existing_ticket(username, access_token, jira_url, ticket_key, payload)

    if source_file_name_match_type == 'regex_match':
        all_local_files = shipyard.files.find_all_local_file_names(
            source_folder_name)
        matching_file_names = shipyard.files.find_all_file_matches(
            all_local_files, re.compile(source_file_name))
        for index, file_name in enumerate(matching_file_names):
            attach_file_to_ticket(
                username,
                access_token,
                jira_url,
                ticket_key,
                file_name)
    else:
        source_file_path = shipyard.files.combine_folder_and_file_name(
            source_folder_name, source_file_name)
        attach_file_to_ticket(
            username,
            access_token,
            jira_url,
            ticket_key,
            source_file_path)
    

