'''
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

'''
Schit - Stores Cryptographic Hashes In Tables

This program creates hashes of files in order to monitor if any changes
have been made. It requires Python version 3.1.X+.
'''

import xml.etree.ElementTree as ET
import hashlib
import sqlite3
import sys
import os

'''
 The main method to use when run as a stand-alone script
'''
def main():
    if len(sys.argv) < 3:
        print('\nSchit - Stores Cryptographic Hashes In Tables')
        print('\npython schit.py [config_file] [init|show|diff|update]')
        print('  init - Creates a new database and deletes the old one.')
        print('  show - Display a listing of the files and their hashes.')
        print('  diff - Check for differences and display them.')
        print('  update - Update the database with modified hashes.')
        print('    (diff must be run before updating)\n')
        exit(0)
    config_file = sys.argv[1]
    command = sys.argv[2]
    try:
        file_monitor = FileMonitor(config_file)
    except Exception as exc:
        print('Invalid config file.')
        print(exc)
        exit(1)
    if command == 'init':
        print('\nInitializing database with hashes.')
        file_monitor.init_database()
        print('Database initialized.')
        exit(0)
    elif command == 'show':
        db_entries = file_monitor.get_database_files()
        for file_loc, orig_hash, new_hash, is_modified in db_entries:
            print(file_loc)
            print('Original Hash:    ' + orig_hash)
            print('New Hash:         ' + new_hash + '\n')
        print('Number of files monitored: ' + str(len(db_entries)))
        exit(0)
    elif command == 'diff':
        print('\nChecking for differences.\n')
        file_monitor.check_existing_files()
        file_monitor.check_new_files()
        modified_entries = file_monitor.get_modified_files()
        for file_loc, orig_hash, new_hash, is_modified in modified_entries:
            print(file_loc)
            print('Original Hash:    ' + orig_hash)
            print('New Hash:         ' + new_hash + '\n')
        print('Number of modified files: ' + str(len(modified_entries)))
        exit(0)
    elif command == 'update':
        print('\nUpdating database entries.')
        file_monitor.update_database()
        print('Database updated.')
        exit(0)


'''
 Monitors files for changes and stores changes in database
'''
class FileMonitor:

    '''
     Required Parameters:
       config_file - string, the configuration to use when monitoring files
    '''
    def __init__(self, config_file):
        # Read in config file
        config_root = ET.parse(config_file).getroot()
        self.database_location = config_root.find('database').text
        
        # Get all of the information from the elements into sets
        self.include_dirs = set()
        self.include_files = set()
        self.exclude_dirs = set()
        self.exclude_files = set()

        for elem in config_root.find('include').findall('directory'):
            self.include_dirs.add(elem.text)
        for elem in config_root.find('include').findall('file'):
            self.include_files.add(elem.text)
        for elem in config_root.find('exclude').findall('directory'):
            self.exclude_dirs.add(elem.text)
        for elem in config_root.find('exclude').findall('file'):
            self.exclude_files.add(elem.text)


    '''
     Gets all modified entries from the database.
     Return:
       list(tuple) - the list of modified database entries
        (str file_location, str original_hash, str new_hash, int is_modified)
    '''
    def get_modified_files(self):
        db_conn = sqlite3.connect(self.database_location)
        db_curs = db_conn.cursor()
        get_all_files_query = '''
         SELECT file_location, original_hash, new_hash, is_modified
         FROM file_data
         WHERE is_modified=1;
        '''
        db_curs.execute(get_all_files_query)
        all_entries = db_curs.fetchall()
        return all_entries
    

    '''
     Gets all the files that are currently on the disk from the configuration
     Return:
       list(string), the absoulte paths of all files found using the config
    '''
    def get_config_files(self):
        # Add all files that were specifically stated to be included
        config_files = set(self.include_files)
        
        # Walk through all included directories
        for include_dir in self.include_dirs:
            for dirpath, dirs, files in os.walk(include_dir):
                # Remove excluded directories
                for dir_name in dirs:
                    if os.path.join(dirpath, dir_name) in self.exclude_dirs:
                        dirs.remove(dir_name)
                # Add all files that are not specifically excluded
                for file_name in files:
                    abs_file_path = os.path.join(dirpath, file_name)
                    if abs_file_path not in self.exclude_files:
                        config_files.add(abs_file_path)
        return config_files


    '''
     Gets the listing of all files from the database.
     Return:
       list(tuple) - the list of database entries
        (str file_location, str original_hash, str new_hash, int is_modified)
    '''
    def get_database_files(self):
        db_conn = sqlite3.connect(self.database_location)
        db_curs = db_conn.cursor()
        get_all_files_query = '''
         SELECT file_location, original_hash, new_hash, is_modified
         FROM file_data;
        '''
        db_curs.execute(get_all_files_query)
        all_entries = db_curs.fetchall()
        return all_entries


    '''
     Hashes a single file with SHA1
     Required parameters:
       file_location - string, the path of the file to hash
     Return:
       string, the SHA1 hash generated from the file's contents
    '''
    def hash_file(self, file_location):
        algorithm = hashlib.sha1()
        file_to_hash = open(file_location, 'rb', 4096)
        for chunk in file_to_hash:
            algorithm.update(chunk)
        file_to_hash.close()
        return algorithm.hexdigest()


    '''
     Initializes the database with the first set of files and hashes.
     Drops any existing tables.
    '''
    def init_database(self):
        db_conn = sqlite3.connect(self.database_location)
        db_curs = db_conn.cursor()
        drop_table_query = 'DROP TABLE file_data;'
        create_table_query = '''
            CREATE TABLE file_data(
              file_location TEXT,
              original_hash TEXT,
              new_hash TEXT,
              is_modified INTEGER
            );
        '''
        insert_query = '''
          INSERT INTO file_data
          VALUES(?, ?, 'Not checked.', 0);
        '''
        try:
            db_curs.execute(drop_table_query)
        except sqlite3.OperationalError as exc:
            pass
        db_curs.execute(create_table_query)

        # Populate the table with hashes
        for file_loc in self.get_config_files():
            try:
                hash = self.hash_file(file_loc)
                entry = (file_loc, hash)
                db_curs.execute(insert_query, entry)
            except Exception as exc:
                pass
        db_conn.commit()
        db_conn.close()


    '''
     Checks the files in the database for changes and commits the difference.
    '''
    def check_existing_files(self):
        update_query = '''
          UPDATE file_data
          SET new_hash=?, is_modified=?
          WHERE file_location=?;
        '''
        database_files = self.get_database_files()
        db_conn = sqlite3.connect(self.database_location)
        db_curs = db_conn.cursor()
        for file_loc, orig_hash, new_hash, is_modified in database_files:
            is_modified = 0
            try:
                tmp_hash = self.hash_file(file_loc)
                if tmp_hash != orig_hash:
                    is_modified = 1
            except Exception as ex:
                is_modified = 1
                tmp_hash = 'File deleted.'
            entries = (tmp_hash, is_modified, file_loc)
            db_curs.execute(update_query, entries)
        db_conn.commit()
        db_conn.close()


    '''
     Checks for new files on the disk and commits difference to database.
    '''
    def check_new_files(self):
        insert_query = '''
          INSERT INTO file_data
          VALUES (?, 'New File.', ?, 1);
        '''
        config_files = self.get_config_files()
        database_entries = self.get_database_files()
        database_files = set()
        for file_loc, orig_hash, new_hash, is_modified in database_entries:
            database_files.add(file_loc)
        db_conn = sqlite3.connect(self.database_location)
        db_curs = db_conn.cursor()
        for file_loc in config_files:
            if file_loc not in database_files:
                try:
                    tmp_hash = self.hash_file(file_loc)
                    entries = (file_loc, tmp_hash)
                    db_curs.execute(insert_query, entries)
                except IOError as exc:
                    pass
        db_conn.commit()
        db_conn.close()


    '''
     Updates the database to accept any changes that have been made.
    '''
    def update_database(self):
        delete_query = 'DELETE FROM file_data WHERE new_hash="File deleted.";'
        update_query = '''
          UPDATE file_data
          SET original_hash=?, new_hash='Not checked.', is_modified=0
          WHERE file_location=?;
        '''
        database_files = self.get_database_files()
        db_conn = sqlite3.connect(self.database_location)
        db_curs = db_conn.cursor()
        db_curs.execute(delete_query)
        for file_loc, orig_hash, new_hash, is_modified in database_files:
            entries = (new_hash, file_loc)
            db_curs.execute(update_query, entries)
        db_conn.commit()
        db_conn.close()


# Required for running the program as a script
if __name__ == '__main__':
    main()
