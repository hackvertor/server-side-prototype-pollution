# Server side prototype pollution scanner

This extension identifies server side prototype pollution vulnerabilities, and requires <strong>Burp Suite v2021.9</strong> or later.

It uses techniques described in the [server side prototype pollution](https://portswigger.net/research/server-side-prototype-pollution) talk by [Gareth Heyes](https://twitter.com/garethheyes).

If you'd like to rate limit your attack, use the Distribute Damage extension.

## How to use the extension

To use this extension simply right-click on a request, go to the extensions menu then server side prototype pollution and choose one of the scan options:

- Body scan - Scans JSON bodies with the techniques
- Body dot scan - Scans JSON bodies using dots, for example __proto__.x 
- Body square scan - Scans JSON bodies using square bracket syntax such as __proto__[x]
- Param scan - Scan JSON inside query parameters and others. Note there has to be existing JSON in the base request. 
- Param dot scan - Scans for JSON inside query parameters using the dot syntax. 
- Param square scan - Scans for JSON inside query parameters using square bracket syntax. 
- Add js property scan - Used to find leaking JavaScript code by adding query parameters such as constructor. 
- JS property param scan - Used to find leaking JavaScript code by manipulating parameters with names like constructor. 
- Async body scan - Attempts to find prototype pollution asynchronously using the --inspect flag. 
- Async param scan - Attempts to find prototype pollution asynchronously using the --inspect flag inside query parameters and others. 
- Full scan - Tries to find prototype pollution using all the methods.

## Techniques

Multiple techniques are used to detect prototype pollution and are described in the PortSwigger blog post.

- JSON spaces
- Async
- Status
- Options
- Blitz
- Exposed headers
- Reflection
- Non reflected property

## Contributions

Contributions and feature requests are welcome.

# Installation
This extension requires Burp Suite 2021.9 or later. To install it, simply use the BApps tab in Burp.

# Development

Linux: `./gradlew build fatjar`

Windows: `gradlew.bat build fatjar`

Grab the output from `build/libs/server-side-prototype-pollution-all.jar`
