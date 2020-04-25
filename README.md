# id-roles
Id-manager roles library   
Simple library for managing access roles. Inspired bij OAUTH scopes.

## Installation

       pip install id-roles
       
## Role structure

Access roles can be described as keys with optional values using a single string.  

        roles_str = "connect admin order[*] customer[read,update]"
        
- Multiple roles are seperated by spaces and may contain an optional values string `[value1,value2]`.
- Values are separated by. `,`  
- Role names may only contain alphanumeric characters and `-`, `_` or `:`.   
- Role value may only contain alphanumeric characters and `-`, `_` or `.`.   
- `[*]` is a special value string that indicated that all values are valid.
- Role names and values are case sensitive