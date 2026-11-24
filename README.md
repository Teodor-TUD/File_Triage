# File Triage & Hash Analysis (Scenario C)



This is a Python command-line tool that triages a folder of files. For each file it checks all of its metadata calculates a SHA-256 hash then checks the hash against the provided reference hashes and finds files that have the same content. It then returns a quick summary and analysis and saves it as a txt and a csv file as well as returning it in the console.



## Why is this useful?



This program has real world application for security analysts. After receiving a folder of files they can simply run this program and have it automatically list which files are new and which are copies of each other. A SHA-256 hash works like a fingerprint so if two files have the exact same content they will always have the same hash. By comparing the hashes of the files with the reference list we can quickly sort the files into three categories: "Known", "Unknown" and "Error" if the file can't be opened.



## Setup



The program requires Python 3.9 or newer to operate. It only uses the standard Python library so no installs are necessary.



## Project structure 



```
file_triage.py           - script that contains all of the code 

hashes_reference.csv     - reference list of all the known hashes 

samples/                 - five safe samples provided within the project resources

dataset_README.txt       - original description of the dataset

reports/                 - automatically created and filled with two files (.txt,.csv) after every run of the code 

README.md                - this file
```



## How to run



Run these from inside the repository folder:



```
python file_triage.py                                   #to analyse the sample folder 

python file_triage.py different_folder                  #to analyse a different folder 

python file_triage.py samples different_reference.csv   #to use a different reference list
```



## Output



The program prints both in console as well as into a .txt and .csv. The console output starts with instruction on how to read the report, it then displays a summary of all of the files. After that every file is listed with its status, size, last modified time, hash and a short note regarding it's status. Unknown files are displayed first due to them needing further attention. The csv and txt files are named with the date and time they were created so that the older reports are not overwritten.
