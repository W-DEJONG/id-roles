# id-roles
Id-manager roles library   
Simple library for managing access roles. Inspired bij OAUTH scopes.

## Installation

       pip install id-roles
       
## Role structure

Roles can be described as keys with optional values using a single string.

        roles_str = "connect admin order[*] customer[read,update]"
        
