# Schit
Stores Cryptographic Hashes In Tables

## Overview
Schit is used to monitor changes to files through a series of SHA1 hashes. These hashes are stored in a sqlite database and are later checked against to see if a file has been changed. In the event that a file has a different SHA1 hash, the user will be notified when the utility is run.

This program requires Python version 3.1.X+ but should run under Python 2.7.X with minimal modifications.

## Usage
A sample configuration has been given in the file `config.xml`
To run the program, execute: `python schit.py [config_file] [init|show|diff|update]`

### Options
`init` - Creates a new database and deletes the old one.

`show` - Display a listing of the files and their hashes.

`diff` - Check for differences and display them.

`update` - Update the database with modified hashes. (diff must be run before updating)

## License
Schit is released under the GPL version 3 license. View the provided file `LICENSE` for more information.
