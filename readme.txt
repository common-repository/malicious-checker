=== Malicious Checker ===
Contributors: gginard
Tags: themes, plugins, security, verification, malicious, checker
Requires at least: 3.8.6
Tested up to: 4.6.1
Stable tag: trunk
License: GPLv2 or later
Donate link: 

Malicious Checker scans all of your files for potentially malicious.

== Description ==
Malicious Checker scans all of your files for potentially malicious..

**What Malicious Checker Does**

Malicious Checker searches the source files of every installed theme and plugin for signs of malicious code. If such code is found, Malicious Checker displays the path to the theme file and plugin file, the line number, and a small snippet of the suspect code.

Then what do you do? Just because the code is there doesn't mean it's not supposed to be or even qualifies as a threat, but most theme authors don't include code outside of the WordPress scope and have no reason to obfuscate the code they make freely available to the web. We recommend contacting the theme author with the code that the script finds, as well as where you downloaded the theme. 
The real value of this plugin is that you can quickly determine where code cleanup is needed in order to safely enjoy your theme.

**History**

Malicious Checker got its start when we repeatedly found obfuscated malicious code in free WordPress themes and WordPress plugins available throughout the web. A quick way to scan a theme for undesirable code was needed, so we put together this plugin.

I have had different problems with malicious code and for that reason I created this plugin.


== Installation ==

After downloading and extracting the latest version of Malicious Checker:

1. Upload `malicious-checker.php` to the `/wp-content/plugins/malicious-checker/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to Appearance -> Malicious Checker in the WordPress Admin
4. The results of the scan will be displayed for each theme and plugin with the filename and line number of any threats.
5. You can click on the path to the theme file to edit in the WordPress Theme Editor and WordPress Plugin Editor

== Changelog ==

= 1.2.7 =
*2016-11-16*

* NEW: Now you can deactivate the files that were potentially malicious and that are not malicious. If you update the plugin or theme you must deactivate it again

= 1.2.6 =
*2016-11-16*

* IMPROVED: Posted in wordpress

= 1.2.5 =
*2016-11-16*

* IMPROVED: Change readme.txt

= 1.2.4 =
*2016-11-15*

* IMPROVED: Compatible with WP 4.6.1
* NEW: Add plugin Checker

= 1.2.0 =
*2016-11-02*

* IMPROVED: Compatible with WP 4.6.0
* NEW: Add theme Checker

= 1.1.0 =
*2016-11-01*

* IMPROVED: Improved the CSS

= 1.0.0 (First Release) =
*2016-11-01*

* NEW: This is the initial release of Malicious Checker
* FIXED: This is the initial release of Malicious Checker
* IMPROVED: This is the initial release of Malicious Checker



== Frequently Asked Questions ==

= What if I find something? =

Contact the theme's original author or theme's original author, to double check if that section of code is supposed to be in the theme in the first place - chances are it shouldn't as there isn't a logical reason have obfuscated code in a theme.

If something is malicious or simply unwanted, *Malicious Checker* tells you what file to edit, you can even just click on the file path to be taken straight to the WordPress Theme Editor or WordPress Plugin Editor.

= What about future vulnerabilities? =

As we find them we will add them to *Malicious Checker*. If you find one, PLEASE let us know:
[Contact gginard](http://www.degabriel.net/contacto/ "Contact gginard"))

== Screenshots ==

1. Malicious Checker Report Page


 == Upgrade Notice ==

 Soon