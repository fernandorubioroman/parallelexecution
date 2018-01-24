# ParallelExecution

This script runs a list of commands or scripts stored in a csv and on all the indicated machines. It supports 
    multiple forests using a xml file that stores multiple credentials, it supports  copying a folder to 
    destination machines (to copy required modules or other files)
    Everything is parallelized for fast execution. The result of the execution of the commands is stored on a xml 
    for further analysis or can be redirected to a variable
    It uses Powershell remoting for remote execution and SMB for prerequisites copy
	
	The module is available in the gallery, to install, in powershell 5 just run from an elevated powershell session
	install-module parallelexecution
	
	Then, use infile help with 
	get-help start-parallelexecution
	
	