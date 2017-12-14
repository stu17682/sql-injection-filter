# sql-injection-filter

Intro
-----
This is a simple SQL injection filter that attempts to detect malicious SQL strings from a pre-defined dataset of malicious (including obfuscated) and benign samples.  Note this tool does not carry out sanitisation of input, where input is transformed into something that conforms to a specification.  Blacklisting was used, since there was no context when creating the dataset, which is needed when creating a whitelist, e.g. a whitelist could be a list of ten users who have access to a certain database.

The Tool
--------
The tool, developed in Java, reads in each sample from the dataset and classifies it as malicious or benign.  It also creates a set of results for the dataset - the number of hits (true positives), the number of misses (false negatives), correct rejections (true negatives) and false alarms (false positives).  These are used in calculating the malicious SQL detection rate (the true positive rate - how well the tool correctly classifies malicious SQL), the rejection rate (the true negative rate - how well the tool correctly classified benign SQL) and the overall accuracy.

The methods used are string searches and regexes.  The tool outputs a list of the malicious strings that were found in the SQL sample.  All the regexes used were written by me using the Oracle Java Documentation.  The resulting output from checking the SQL samples using the regexes includes both regexes that returned a match, and those that didn't, so we can inspect them to see which were triggered and also lets us tune them during development in case of errors.  The functionality is found in the two methods sqlStringChecker() and sqlRegexChecker().  The tool converts all samples to lower case, removing any obfuscation attempts by mixing upper and lower case letters.

The Dataset
-----------
If you want the original test dataset, please email me on smillar09@qub.ac.uk.  I may upload it also.  But you can easily use your own too.  10% of the malicious samples and 10% of the benign samples were randomly removed and not used for tuning the tool during development.  The patterns themselves were selected from studying the remaining malicious samples in the dataset.  I'd recommend you do this too, to avoid data-snooping, so that you have two datasets.  

Data-snooping
-------------
I get avoid data-snooping may be easier said than done! :) But if you are new to this, hear me out - we don't want to tune the tool too closely to the whole dataset, or it might not generalise well to other SQL samples.  The principle is that if a dataset has been affected or influenced any step in the development process, its ability to assess the outcome has been compromised.  Looking at the dataset too closely and too early in the process is known as data-snooping.  When we datasnoop, we thing we end up with better performance.  When we look at the dataset we are vulnerable to designing the tool depending on the idiosyncrasies of that dataset. So a filter tool performs well on that dataset but it is not known how it performs on an independently generated dataset.  If accuracy is too high then the tool may be overfitted.

