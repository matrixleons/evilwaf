import os
import re

from core.colors import run, que, good, green, end, info
from core.requester import requester


def updater():
    """Update the current installation."""
    print('%s Checking for updates' % run)
    # Changes must be separated by ;
    changes = '''initial evilwaf release;custom updates for evilwaf'''
    
    try:
        latest_commit = requester('https://raw.githubusercontent.com/matrixleons/evilwaf/main/core/updater.py', host='raw.githubusercontent.com')
        
        # Check if we got a valid response
        if not latest_commit or latest_commit == 'dummy':
            print('%s Could not check for updates. Check your internet connection.' % info)
            return
            
        # Just a hack to see if a new version is available
        if changes not in latest_commit:
            changelog = re.search(r"changes = '''(.*?)'''", latest_commit)
            
            # FIX: Check if regex found a match
            if changelog:
                # Splitting the changes to form a list
                changelog = changelog.group(1).split(';')
                print('%s A new version of EvilWAF is available.' % good)
                print('%s Changes:' % info)
                for change in changelog: # print changes
                    print('%s>%s %s' % (green, end, change))
            else:
                # If no changelog found, show generic message
                print('%s A new version of EvilWAF is available.' % good)
                print('%s Changes: Various improvements and bug fixes' % info)

            current_path = os.getcwd().split('/')
            folder = current_path[-1]
            path = '/'.join(current_path)
            choice = input('%s Would you like to update? [Y/n] ' % que).lower()

            if choice != 'n':
                print('%s Updating EvilWAF' % run)
                os.system('git clone --quiet https://github.com/matrixleons/evilwaf %s' % (folder))
                os.system('cp -r %s/%s/* %s && rm -r %s/%s/ 2>/dev/null' % (path, folder, path, path, folder))
                print('%s Update successful!' % good)
        else:
            print('%s EvilWAF is up to date!' % good)
            
    except Exception as e:
        print('%s Error checking for updates: %s' % (info, str(e)))
