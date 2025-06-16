# Representing the Significance of Hashing in Password Storage
## CMPE 412 -- Networks & Secutiy

This project discusses the critical role of hashing in securing passwords within software
applications. By implementing a diverse array of hashing methods, including simple hashing,
peppered hashing, iterated hashing, XOR hashing, rotated hashing, a “crazy” hash, and finally
we see the role of AI with a simple AI-generated hash. Along with the storage of passwords, a
user-friendly login/sign-up interface is presented. This project showcases how these techniques
effectively safeguard passwords. The interface provides users with a real-time visualization of
the hashing process, showing the importance of password protection. This project serves as a
simple demonstration of how incorporating hashing algorithms can bolster software security by
preventing unauthorized access to user data.


The project's scope contains the design and implementation of a variety of hashing algorithms,
each with its own somewhat unique approach to password protection. These algorithms
transform passwords into irreversible hash values, making it computationally infeasible to
recover the original password from the hash. This one-way transformation is fundamental in
securing passwords, as even if the hashed password is compromised, the original password
remains unknown. Additionally, hashing algorithms provide quick and efficient data retrieval as
opposed to other methods of fetching data. So, not only do they provide a security blanket but
they are computationally fast to use.


Furthermore, this project emphasizes the significance of incorporating additional security
measures, such as salt or pepper values, in the hashing process. These randomly generated
values, when combined with the password before hashing, introduce further complexity, making
it substantially more challenging for attackers to crack the hashes using techniques like rainbow
tables or dictionary attacks. These hash-cracking techniques involve using known words or
phrases, these are then hashed using known algorithms. Once this is done attackers will
attempt to reverse the hash. Adding salt to the hash can strengthen the prevention of these
attacks. In my code, the use of salt is very minimal and barebones, and in real world examples,
the scope would be much larger.


By integrating robust hashing methods with a simple but user-friendly interface, this project
effectively demonstrates the practical application of password security techniques in software
development. This hands-on approach not only educates users about the importance of
password protection but also empowers developers to prioritize security considerations in their
software designs. Passwords are stored with usernames in a dictionary, the users are stored
with the respective salt values associated to the passwords, and the hashing method used is
stored, this is essential in the login process. Showing these simple but powerful steps in
password security shows the user that their data is safe, and these methods are continuously
being improved upon.
