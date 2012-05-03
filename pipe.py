import gdata.docs.service
import gdata.docs.data
import gdata.docs.client
import gdata.spreadsheet.service

import keyring
import getpass
import ConfigParser
import tempfile,os,sys
import xattr
import iso8601
import calendar
from datetime import datetime

import sys

from optparse import OptionParser

def auth(client,username,password):
    try:
        return client.ClientLogin(username, password, client.source)
    except:
        return False

def main():
    parser = OptionParser()
    parser.add_option("-c", "--command", dest="command",
                      help="run COMMAND", metavar="COMMAND")
    parser.add_option("-d", "--document", dest="docid",
                      help="Specify document")
    parser.add_option("-w", "--write", dest="outfile")
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose", default=True,
                      help="don't print status messages to stdout")

    (options, args) = parser.parse_args()

    (username,client) = get_client()
    if options.command == "ls":
        list_files(client)
    elif options.command == "get":
        get_doc(client,username,options.docid,options.outfile)
    elif options.command == "update":
        revise_doc(client,username,options.docid)

def revise_doc(client,username,docid):
    fd,temp_path = tempfile.mkstemp()
    tf = os.fdopen(fd, "w")
    for line in sys.stdin:
        tf.write(line)
    tf.close()
    entry = client.GetResourceById(docid)

    ms = gdata.data.MediaSource(file_path=temp_path, content_type='text/tab-separated-values')

    client.UpdateResource(entry,media=ms,new_revision=True)
    os.remove(temp_path)

def list_files(client):
    # Query the server for an Atom feed containing a list of your documents.
    #documents_feed = client.GetResources(uri='/feeds/default/private/full/-/spreadsheet')

    documents_feed = client.GetResources(uri='/feeds/default/private/full/-/spreadsheet')
    # Loop through the feed and extract each document entry.
    for document_entry in documents_feed.entry:
      # Display the title of the document on the command line.
      print document_entry.title.text
      print document_entry.resource_id.text

def get_client():
    client = gdata.docs.client.DocsClient(source='spreadsheet-pipe')
    client.ssl = True  # Force all API requests through HTTPS
    client.http_client.debug = False  # Set to True for debugging HTTP requests

    # config file init
    config_file = 'googlepipe.cfg'
    config = ConfigParser.SafeConfigParser({
                'username':'',
                })
    config.read(config_file)
    if not config.has_section('gdocs_login'):
        config.add_section('gdocs_login')

    username = config.get('gdocs_login','username')
    password = None
    if username != '':
        password = keyring.get_password('gdocs_login', username)

    if password == None or not auth(client,username, password):

        while 1:
            username = raw_input("Username:\n")
            password = keyring.get_password('gdocs_login',username)
            if password == None:
                password = getpass.getpass("Password:\n")

            if auth(client,username, password):
                break
            else:
                print "Authorization failed."

        # store the username
        config.set('gdocs_login', 'username', username)
        config.write(open(config_file, 'w'))

        # store the password
        keyring.set_password('gdocs_login', username, password)

    # Spit back a username/client combo
    return [username,client]

def get_doc(client,username,doc_id,filename):
    spreadsheets_client = gdata.spreadsheet.service.SpreadsheetsService(source='spreadsheet-pipe')
    spreadsheets_client.ClientLogin(username, keyring.get_password('gdocs_login', username), client.source)
    entry = client.GetResourceById(doc_id)
    etag = None
    if filename and os.path.exists(filename):
        try:
            etag = xattr.getxattr(filename,'user.etag')
        except:
            pass

    if not etag is None:
        if entry.etag == etag:
            print >> sys.stderr, "Matching Etag, not downloading" 
            return
        else:
            time = calendar.timegm(iso8601.parse_date(entry.updated.text).timetuple())
            if time == os.stat(filename).st_mtime:
                print >> sys.stderr, "Modification times unchanged, not downloading"
                return
            print >> sys.stderr, "No matching Etag or modification time, downloading ("+etag+"/"+entry.etag+")"

    # substitute the spreadsheets token into our client
    docs_token = client.auth_token
    doc_type = entry.GetResourceType()

    if doc_type == "text/plain" or doc_type == "application/octet-stream":
        opts = { }
        ssheets_auth=None
    else:
        opts = { 'gid' : 0, 'exportFormat':'tsv'}
        ssheets_auth=gdata.gauth.ClientLoginToken(spreadsheets_client.GetClientLoginToken())

    if not filename is None:
        client.DownloadResource(entry,filename,opts,auth_token=ssheets_auth)
        xattr.setxattr(filename,'user.etag',entry.etag)
        time = calendar.timegm(iso8601.parse_date(entry.updated.text).timetuple())
        os.utime(filename, (time,time))
    else:
        print client.DownloadResourceToMemory(entry,opts,auth_token=ssheets_auth)
        print "\n\n"

    client.auth_token = docs_token  # reset the DocList auth token

if __name__ == "__main__":
    main()

