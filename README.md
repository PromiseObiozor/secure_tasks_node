SecureTasks – Secure Application Programming Project
This project is a small Node.js/Express task manager application that I built to demonstrate both insecure coding practices and how to fix them properly. The repository contains two separate branches:
insecure branch → intentionally vulnerable
secure branch → fixes applied following secure coding principles
Both versions look and behave the same for the user, but the code under the hood is very different.

Features
- User registration
- Login and logout
- Create tasks
- View and search your own tasks
- Demonstration of common security vulnerabilities (insecure branch)
- Secure version using proper password hashing, safer SQL, escaped views, and improved session handling


Branches
Insecure Branch
This branch intentionally includes:
- SQL injection (string-built SQL in search)
- Stored XSS (raw HTML output in EJS)
- Reflected XSS (unescaped query parameter)
- DOM-based XSS (innerHTML)
- Plain-text passwords
- Weak session cookie settings
- Missing security headers
- Sensitive data logged to console
This version is for testing and learning only.


Secure Branch
The secure version includes:
- Bcrypt password hashing
- Parameterised SQL queries
- Escaped EJS output (<%= %>)
- DOM sanitisation using .textContent
- Improved session cookie settings
- Basic security headers
- No password logging
The secure branch keeps the same functionality but removes the vulnerabilities.
