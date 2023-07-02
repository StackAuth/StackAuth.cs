# StackAuth.online Licensing Project

This API serves as a layer that simplifies communication between Your Application and the server

> You can access the documentation of the API at https://docs.stackauth.online

# Getting started

### Grab API Secret, AID, and Activate Key

* **Must have an account and purchase a subscription at https://stackworkshop.com/packages **
* **Step 1** : Login to your panel and create your application
* **Step 2** : Your application secret, AID, and Activate key will be next to your application name
* **Step 3** : Copy your secret, AID, and ActivateKey and store it somewhere

### Connecting panel to program
Now that you have your ``AID`` , ``Secret``, and  ``ActivateKey`` use it to initialize and connect your application to our servers
```
 OnProgramStart.Initialize("APPNAME", "AID", "PROGRAMSECRET", "VERSION", "ActivateKey, false, false);
 
 The two bool parameters at the end of Initialize is AntiDebug and Bad Process Check. These are turned off by default. Just change the false to True to turn them on.
 The Procress Check does add a little delay to the program launch for it to check for programs to crack your application.
 These option will not protect you from **hackers** that know what they are doing, Just wannabe's!
```
## Example
```
 OnProgramStart.Initialize("StackApp", "269868", "t5d7rzzbrdAHmfWTGmuTUazjLIvWk", "1.0", "Stack-1982", false, false);
```
> After a successful initialization, the server will send back the following information on your application based on the settings you have picked
* ``ApplicationSettings.Name`` : Application name
* ``ApplicationSettings.Status`` : Application Enabled/Disabled
* ``ApplicationSettings.DeveloperMode`` : DeveloperMode Enabled/Disabled
* ``ApplicationSettings.Hash`` : Applications md5 hash to check integrity
* ``ApplicationSettings.Version`` : Applications version
* ``ApplicationSettings.UpdateLink`` : Applications link that it updates from if version is updated
* ``ApplicationSettings.Freemode`` : Freemode Enabled/Disabled
* ``ApplicationSettings.Login`` : Login Enabled/Disabled
* ``ApplicationSettings.Register`` : Login Enabled/Disabled
*  ``ApplicationSettings.TotalUsers`` : Total users registered for application
## Login

```
 if (StackAPI.Login(username, password))
                    {
                    //Code you want to do here on successful login
MessageBox.Show("You have successfully logged in!", OnProgramStart.Name, MessageBoxButton.OK, MessageBoxImage.Information);
                    }
```
> After a successful login, the server will send back the following information on your user
* ``User.Username`` : Users username 
* ``User.ID`` : Users ID
* ``User.Email`` : Users email
* ``User.HWID`` : Users hardware ID
* ``User.IP`` : Users IP
* ``User.UserVariable`` : Users variable
* ``User.Rank`` : Users rank
* ``User.Expiry`` : Users expiry
* ``User.LastLogin`` : Users last login
* ``User.RegisterDate`` : Users registration date
* ``User.ProfilePicture`` : Users profile picture link
## Register

```
 if (StackAPI.Register(username, password, email, license))
                    {
                    //Code you want to do here on successful register
MessageBox.Show("You have successfully registered!", OnProgramStart.Name, MessageBoxButton.OK, MessageBoxImage.Information);
                    }
```
## Extend Subscription
```
 if (StackAPI.ExtendSubscription(username, password, token))
                {
                    MessageBox.Show("You have successfully extended your subscription!", OnProgramStart.Name, MessageBoxButton.OK, MessageBoxImage.Information);
                    // Do code of what you want after successful extend here!
                }
```
## All in one - strictly key based - login & register with one
```
   if(StackAPI.AIO(KEY))
                {
                    //Code you want to do here on successful login
                    MessageBox.Show("Welcome back to my application!", OnProgramStart.Name, MessageBoxButton.OK, MessageBoxImage.Information);
                    Process.GetCurrentProcess().Kill(); // closes the application
                }
                else
                {
                    //Code you want to do here on failed login
                    MessageBox.Show("Your key does not exist!", OnProgramStart.Name, MessageBoxButton.OK, MessageBoxImage.Error);
                    Process.GetCurrentProcess().Kill(); // closes the application
                }
```
## Log Action (discord webhook must be added to the panel to use logs)

```
 StackAPI.Log("USERNAMEHERE", "ACTION HERE");
```
## Update Profile Picture

```
 StackAPI.ChangeProfilePic(path);
```
## Reset HWID

```
 StackAPI.ResetHwid(username, password);
```
## Ban

```
 StackAPI.Ban(reason);
```
