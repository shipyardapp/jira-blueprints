import argparse
import sys
import requests
from requests.auth import HTTPBasicAuth
import shipyard_utils as shipyard
import code
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
    parser.add_argument('--summary', dest='summary', required=True)
    parser.add_argument('--description', dest='description', required=True)
    parser.add_argument('--issue-type', dest='issue_type', required=True)
    parser.add_argument('--assignee', dest='assignee', required=False)
    parser.add_argument('--custom-json', dest='custom_json', required=False)
    args = parser.parse_args()
    return args


def generate_payload(project_key, summary,
                     description, issue_type, assignee_user_id):
    """ Creates a JIRA Ticket json payload for use with the Jira create ticket
    rest API.
    see: https://developer.atlassian.com/server/jira/platform
                /jira-rest-api-examples/#creating-an-issue-examples
    for an example of a basic payload.
    """

    payload = {
        "fields": {
            "project":
            {
                "key": project_key
            },
            "summary": summary,
            "description": description,
            "issuetype": {
                "name": issue_type
            },
            "assignee": {
                "id": assignee_user_id
            }
        }
    }
    return payload


def create_ticket(username, token, jira_url, payload):
    """ Triggers the Create Issue API and adds a new ticket onto JIRA"""

    create_ticket_endpoint = f"https://{jira_url}/rest/api/2/issue"
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.post(create_ticket_endpoint,
                             headers=headers,
                             json=payload,
                             auth=HTTPBasicAuth(username, token)
                             )

    if response.status_code == 201:  # created successfuly
        new_ticket_key = response.json()['key']
        print(f"Ticket created successfully with Key name: {new_ticket_key}")
        return response.json()

    elif response.status_code == 401:  # Permissions Error
        print(
            "You do not have the required permissions to create an issue in ",
            "this project")
        sys.exit(exit_codes.INVALID_CREDENTIALS)

    elif response.status_code == 400:  # Bad Request
        print("JIRA responded with Bad Request Error. ",
              f"Response message: {response.text}")
        sys.exit(exit_codes.BAD_REQUEST)

    else:  # Some other error
        print(
            f"an Unknown HTTP Status {response.status_code} and response occurred when attempting your request: ",
            f"{response.text}")
        sys.exit(exit_codes.UNKNOWN_ERROR)


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


def main():
    args = get_args()
    username = args.username
    access_token = args.access_token
    project_key = args.project_key
    jira_url = args.jira_url

    summary = args.summary
    description = args.description
    issue_type = args.issue_type
    assignee = args.assignee

    if assignee:
        users = get_all_users(username, access_token, jira_url)
        assignee_user_id = find_user_id(users, assignee)
    else:
        assignee_user_id = None
    payload = generate_payload(project_key, summary,
                               description, issue_type, assignee_user_id)
    # add custom fields if they exist
    if args.custom_json:
        payload['fields'].update(args.custom_json)

    issue_data = create_ticket(username, access_token, jira_url, payload)
    issue_id = issue_data['id']

    # save issue to responses
    issue_data_filename = shipyard.files.combine_folder_and_file_name(
        artifact_subfolder_paths['responses'],
        f'create_ticket_{issue_id}_response.json')
    shipyard.files.write_json_to_file(issue_data, issue_data_filename)


if __name__ == "__main__":
    main()
