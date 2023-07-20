# BurpSuite SourceMap

Introducing a Burp Extension for Parsing JavaScript Source Maps.

In the realm of modern web development, it has become customary to "minify" JavaScript files in order to optimize asset sizes and enhance website loading times. However, this optimization process renders the code highly intricate and challenging to analyze effectively.

Our innovative Burp Extension addresses this issue by enabling a seamless parsing of JavaScript source maps. By automatically initiating an additional HTTP request with the ".js.map" extension whenever a ".js" file is loaded, the extension efficiently determines the availability of a corresponding map file. When identified, the map file is unpacked and seamlessly incorporated into the Burp sitemap for comprehensive analysis.

Moreover, for convenience, this functionality can also be activated by selecting JavaScript URLs and subsequently clicking on "Do Passive Scan."



## Installation
* Download the extension .py file.
* Open Burp -> Extender -> Extensions -> Add -> Choose the file.
