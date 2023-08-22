# BurpSuite JS Map Hunter

Introducing a Burp Extension for Parsing JavaScript Source Maps.

In the realm of modern web development, it has become customary to "minify" JavaScript files in order to optimize asset sizes and enhance website loading times. However, this optimization process renders the code highly intricate and challenging to analyze effectively.

Our innovative Burp Extension addresses this issue by enabling a seamless parsing of JavaScript source maps. By automatically initiating an additional HTTP request with the ".js.map" extension whenever a ".js" file is loaded, the extension efficiently determines the availability of a corresponding map file. When identified, the map file is unpacked and seamlessly incorporated into the Burp sitemap for comprehensive analysis.

Moreover, for convenience, this functionality can also be activated by selecting JavaScript URLs and subsequently clicking on "Do Passive Scan."

Note: It is recommended to disable the extension when not required, as it will issue a request for the .js.map file whenever a .js file is loaded.

## Features:

- **JS files are never sent to third-party servers**. This ensures that your sensitive data is never exposed to unauthorized parties. The unpacking process is performed locally on Burp Suite, so your data remains secure throughout the process.

- **Unpacked JavaScript code is added to the sitemap for easier review**. This makes it easy to see all of the Unpacked JavaScript code. This can help you to identify potential security vulnerabilities.

- **Better static analysis can be performed using BurpSuite and other extensions**. This is because the unpacked JavaScript code is loaded into the sitemap, which makes it available for analysis. Easily extract URLs, paths, secrets, and other interesting data with Burp passive scan.


## Installation
* Download the extension .py file.
* Open Burp -> Extender -> Extensions -> Add -> Choose the file.
