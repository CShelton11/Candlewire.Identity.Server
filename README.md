# Candlewire.Identity.Server
Enhanced Identity Server UI

This project was created to provide a little more to identity server in the form of UI enhancements and improved application flow.
My hope is to continue improving upon the UI with the help of others and to include new features such the following:

1.  Corporate signin and restrictions
2.  More configurable profile editing options 
    - like the ability for users to view/edit addresses through simple configuration
3.  Ability for accounts to be created (through redirect) given information received from external applications.
4.  Anything else that you can think of that might be useful to others.

The idea, is that different people have different needs.  Someone might want first name, someone might want last name, someone might want addresses, someone might want nickname, etc...
These should already be included as part of the UI and should be made available through simple config changes.

I also would like for microservices architecture to be a consideration when developing, so other applications can be notified (via event bus) of changes made to accounts.
