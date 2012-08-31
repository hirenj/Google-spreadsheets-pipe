#!/usr/bin/env python

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

import signal

import sys

from optparse import OptionParser

global interrupted
interrupted = False

def signal_handler(signal, frame):
        print >> sys.stderr, 'Google pipe: Aborting'
        interrupted = True
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

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
    parser.add_option("-s", "--sheet", dest="sheet", default=0)
    parser.add_option("-a", "--archive", dest="archive", help="Archive doc and apply specified title")
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose", default=True,
                      help="don't print status messages to stdout")

    (options, args) = parser.parse_args()
    global verbose
    verbose = options.verbose

    (username,client) = get_client()
    if options.command == "login":
        print client.auth_token.token_string
    if options.command == "ls":
        list_files(client,options.docid)
    elif options.command == "get":
        get_doc(client,username,options.docid,options.outfile,sheet=options.sheet)
    elif options.command == "update":
        if options.archive:
            revise_doc_with_backup(client,username,options.docid,options.archive)
        else:
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

def revise_doc_with_backup(client,username,docid,new_title):
    entry = client.GetResourceById(docid)
    new_entry = client.CopyResource(entry,entry.title.text)
    entry.title.text=new_title
    client.UpdateResource(entry)
    for uri in entry.InCollections():
        folder=client.GetResourceBySelfLink(uri.href)
        client.MoveResource(new_entry,folder,True)
    revise_doc(client,username,docid)



def list_files(client,docid=None):
    # Query the server for an Atom feed containing a list of your documents.
    #documents_feed = client.GetResources(uri='/feeds/default/private/full/-/spreadsheet')

    if docid != None:
        print client.GetResourceById(docid).title.text
        return

    documents_feed = client.GetResources(uri='/feeds/default/private/full?max-results=10000')
    # Loop through the feed and extract each document entry.
    for document_entry in documents_feed.entry:
      # Display the title of the document on the command line.
      print document_entry.resource_id.text+"\t"+document_entry.title.text

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

    if 'GPIPE_TOKEN' in os.environ:
        client.auth_token = gdata.gauth.ClientLoginToken(os.environ['GPIPE_TOKEN'])
        return [username,client]

    print >> sys.stderr, "Performing a new login"


    password = None
    if username != '':
        password = keyring.get_password('gdocs_login', username)

    if password == None or not auth(client,username, password):

        while not interrupted:
            username = raw_input("Username:\n")
            password = keyring.get_password('gdocs_login',username)
            if password == None:
                password = getpass.getpass("Password:\n")

            if auth(client,username, password):
                break
            else:
                print >> sys.stderr, "Authorization failed."

        # store the username
        config.set('gdocs_login', 'username', username)
        config.write(open(config_file, 'w'))

        # store the password
        keyring.set_password('gdocs_login', username, password)

    # Spit back a username/client combo
    return [username,client]

def get_doc(client,username,doc_id,filename,sheet=0):
    spreadsheets_client = gdata.spreadsheet.service.SpreadsheetsService(source='spreadsheet-pipe')
    spreadsheets_client.ClientLogin(username, keyring.get_password('gdocs_login', username), client.source)
    entry = client.GetResourceById(doc_id)

    if verbose:
        print >> sys.stderr, "Retrieving \""+entry.title.text+"\""

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
        opts = { 'gid' : sheet, 'exportFormat':'tsv'}
        ssheets_auth=gdata.gauth.ClientLoginToken(spreadsheets_client.GetClientLoginToken())

    if not filename is None:
        client.DownloadResource(entry,filename,opts,auth_token=ssheets_auth)
        xattr.setxattr(filename,'user.etag',entry.etag)
        time = calendar.timegm(iso8601.parse_date(entry.updated.text).timetuple())
        os.utime(filename, (time,time))
    else:
        print client.DownloadResourceToMemory(entry,opts,auth_token=ssheets_auth)
        print "\n\n"

    if verbose:
        print >> sys.stderr, "Retrieved \""+doc_id+"\""

    client.auth_token = docs_token  # reset the DocList auth token

if __name__ == "__main__":
    main()

