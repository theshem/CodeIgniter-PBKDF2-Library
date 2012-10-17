#CodeIgniter PBKDF2 Library
**PBKDF2 PHP Class Library for CodeIgniter.**

PBKDF2 (Password-Based Key Derivation Function) is a key stretching algorithm.
It can be used to hash passwords in a computationally intensive manner,
so that dictionary and brute-force attacks are less effective.

##HOW TO USE

###1) Customizing the PBKDF2 (optional)

The following is a list of all the preferences you can pass to the initialization function to customize PBKDF2 encryption.

```PHP
// HMAC hashing algorithm
$config['algorithm'];
```
PBKDF2 uses **SHA-256** by default; If the algorithm does not exist, `sha256` will be set.

```PHP
// Number of iterations to make 
$config['iterations'];
```
It is set to **1000** by default, recommended by [RFC#2898](http://www.ietf.org/rfc/rfc2898.txt).

```PHP
// Length of hashed password
$config['hash_length'];
```
It is set to **32** characters (128-bit) by default.

```PHP
// Length of hashed salt
$config['salt_length'];
```
It is set to **32** characters (128-bit) by default.

####Usage:
Example of Initializing the library
```PHP
// Load library into controller
$this->load->library('pbkdf2');

$config['algorithm'] = 'whirlpool';
$config['iterations'] = 500;
$config['hash_length'] = 64;
$config['salt_length'] = 16;

$this->pbkdf2->initialize($config);
```
_ _ _

###2) Explanation of `Encrypt` Method

**Syntax:**
```PHP
encrypt( string $password [, mixed $good_hash = NULL [, bool $object_output = FALSE]] )
```

**Usage:**
* **First**

	```PHP
	$pbkdf2 = $this->pbkdf2->encrypt($password);
	```
	> **Return:**
	>An associative array with 'salt', 'password', 'hash' keys
	which vaule of 'hash' is concatenation of 'salt' and 'password'.

* **Second**

	```PHP
	$pbkdf2 = $this->pbkdf2->encrypt($password, TRUE);
	```
	> **Return:**
	>An object (stdClass) with 'salt', 'password', 'hash' properties
	which vaule of 'hash' is concatenation of 'salt' and 'password'.

* **Third**

	```PHP
	$pbkdf2 = $this->pbkdf2->encrypt($password, $good_hash);
	```
	Using `$good_hash` which has been fetched from database to generate `$password` hash while `$good_hash` could be **salt** or **hash** (concatenation of salt and password).

	> **Return:**
	>An associative array with 'salt', 'password', 'hash' keys
	which vaule of 'hash' is concatenation of 'salt' and 'password'.

* **Fourth**

	```PHP
	$pbkdf2 = $this->pbkdf2->encrypt($password, $good_hash, TRUE);
	```
	Using `$good_hash` which has been fetched from database to generate `$password` hash while `$good_hash` could be **salt** or **hash** (concatenation of salt and password).

	> **Return:**
	>An object (stdClass) with 'salt', 'password', 'hash' properties
	which vaule of 'hash' is concatenation of 'salt' and 'password'.

`salt` and `password` *indexes/properties* are **128-bit**|16-byte|32-char hash value by default. so `hash` would be double (**256-bit**).
_ _ _

###3) Register user

####Step 1:

Load `pbkdf2` library into your controller:

```PHP
$this->load->library('pbkdf2');
```

####Step 2:

Encrypt user's password sent from login.

```PHP
// get password, which has been sent by using POST method
$password = $this->input->post('password', TRUE);

$pbkdf2 = $this->pbkdf2->encrypt($password);
```
Register user by using `$pbkdf2['password']` as user's password and storing `$pbkdf2['salt']` in seperate column for lateral using

**OR**

Register user by using `$pbkdf2['hash']` as user's password which has been recommended; no need to store user's `salt` seperately.

>**NOTE:** Usernames **MUST** be unique. be ensured that users aren't able to choose duplicate usernames. make some strictions on registering users.

_ _ _

###4) Logging in user

####Step 1:

Load `pbkdf2` library into your controller:

```PHP
$this->load->library('pbkdf2');
```

####Step 2:

Fetch user's password using posted username.

Assuming a model named `user.php` exists, which returns an associative array contains user's `password` and *whatever-you-need* from database using posted `username`.

```PHP
$username = $this->input->post('username', TRUE);
// get password for the next step
$password = $this->input->post('password', TRUE);
$user = $this->user->get_user($username);
```
>**NOTE:** Usernames **MUST** be unique. be ensured that users aren't able to choose duplicate usernames. make some strictions on registering users.

####Step 3:

Check if the given password is exactly equal to passwoed is stored in database.

In the example below, it is assumed that concatenation of `salt` and `password` which called `hash` is used as user's password. the *encrypt* method select the `salt` automatically.

> NOTE: If you want to store `salt` in database separately, you MUST pass the `salt` as second parameter to encrypt method.

```PHP
$pbkdf2 = $this->pbkdf2->encrypt($password, $user['password']);

// check if user exists
if ($user) {
	
	if ($pbkdf2['hash'] === $user['password']) {

		// do login and/or blag blah blah...

	}
}
```

## License

[CodeIgniter PBKDF2 Library](https://github.com/qolami/CodeIgniter-PBKDF2-Library/) was created by [Hashem Qolami](http://qolami.com) and released under the [MIT License](http://opensource.org/licenses/MIT), based on [RFC#2898](http://www.ietf.org/rfc/rfc2898.txt).  
Feel free to send me email if you have any problems.

Thanks,  
-Hashem Qolami <<hashem@qolami.com>>