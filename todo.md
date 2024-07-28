## Left to Implement
- log: 
- error handling: 

### Things to Recheck/confirm: remove after checking if fine
- the STOP signal when sending files to clients- currently just a size 2 buf
- make sure the command indexes are uniform throughout
- where is the client writing file?
- fix exits and returns

- prints to ss for client requests(ip, port, command, etc)


## Checklist

### Error Codes [20 Marks]

    - [ ] Error Handling: Define a set of error codes that can be returned when a client’s request cannot be accommodated. For example, the NM should return distinct error codes for situations where a file is unavailable because it doesn’t exist and when another client is currently writing to the file. Clear and descriptive error codes enhance the communication of issues between the NFS and clients.

### Bookkeeping [20 Marks]

    - [ ] Logging and Message Display: Implement a logging mechanism where the NM records every request or acknowledgment received from clients or Storage Servers. Additionally, the NM should display or print relevant messages indicating the status and outcome of each operation. This bookkeeping ensures traceability and aids in debugging and system monitoring.
    - [ ] IP Address and Port Recording: The log should include relevant information such as IP addresses and ports used in each communication, enhancing the ability to trace and diagnose issues.

### Pointers
    - [ ] Cite your resources if you take any ideas or code
    - [ ] Lastly, make necessary assumptions