Justin Kim
(jyk2149)


1. Initializing an archive and adding files
    - Archives are created by the "add" command:
        ./cstore add [-p password] "archivename" file1 file 2..
    - An empty archive can not be created. An archive will delete if there are no files inside of them.
    - File names can not exceed 100 characters
    - File size can not exceed 999999999999 bytes
        - These restrictions are so that the headers of each file can remain a consistent fixed size
2. Extracting Files
    - Files can be extracted from the archive by the "extract" command:
        ./cstore extract [-p password] archivename file1 file2..
    - Extracts files to the current working directory
    - It will overwrite files in the working directory
3. Deleting Files
    - Files can be deleted from archives by the "delete" command:
        ./cstore delete [-p password] archivename file1 file2
    - If the last file is deleted from an archive, then the entire archive will be deleted
4. List Files in Archives
    - A list of files in an archive can be accessed through the list command
        ./cstore list archivename



Tests:
    - Can run tests using make test
    - Tests all four functions and compares extraction to a source file


AES Mode: CBC
    - I implemented CBC because it was easily derived from the EBC mode given from the library.
    - CBC is more secure than EBC because it is missing information between the blocks of ciphertext so
      an attacker would have more trouble trying fill in the missing pieces than in EBC.

Integrity Check
    - I used HMAC256 to integrity check my archive. At the end of an archive, a 32 BYTE HMAC cypher is appended
      derived from the original ciphertext. That way, even with the right password, if the file was altered,
      the HMAC generated from the same password would not match the old HMAC. By recalculating this on every update
      (delete and add), the archive is ensured to have integrity checking.
