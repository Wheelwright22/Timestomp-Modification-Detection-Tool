# "Detecting Timestomping Relies On Finding Traces Of The Very Act Itself, Or Finding Inconsistencies Introduced By The Tampering."

import subprocess
import re
import datetime
import pytsk3
import argparse
import sqlite3
import csv

##############################################################################

parser = argparse.ArgumentParser(description = "Detect Timestamp Modification")

# By Creating A Group, argparse Will Make Sure That Only One Of The Arguments In The argsgroup Is Given On The Command Line.
# The "required = True" Means That It Will Require That One Of Them Is Present.
argsgroup = parser.add_mutually_exclusive_group(required = True)

argsgroup.add_argument("-inode")
argsgroup.add_argument("-scanall", action = "store_true")
# The Action "store_true" Stores A "True" Boolean When The Argument Is Passed
# To Kick Off The For-Loop, You Would Check if args.scanall == "True"


parser.add_argument("-memdump", required = False)
parser.add_argument("-image", required = True)
parser.add_argument("-profile", required = False)

args = parser.parse_args()

# Throw An Error If You Try To Use The -profile Flag Without The -memdump Flag.
if args.profile and args.memdump is None:
	parser.error("To Use The -profile Flag, You Must Also Use The -memdump Flag!")

# You Can Reference Arguments Like This: args.inode, args.image, args.memdump

suppliedProfile = args.profile
memoryFile = args.memdump
imageFile = args.image
suppliedinode = args.inode

##############################################################################

try:
    sqliteConnection = sqlite3.connect('Timestomp_Findings_Database.db')
    sqlite_create_table_query = '''CREATE TABLE TIMESTOMP_FINDINGS (
                                ID INTEGER PRIMARY KEY,
                                Name TEXT NOT NULL,
                                File_Type TEXT NOT NULL,
 				Millisecond_Test TEXT NOT NULL,
				Predate_Test TEXT NOT NULL,
				Parent_Directory_Test TEXT NOT NULL,
				SI_CREATED TEXT NOT NULL,
				SI_FILE_MODIFIED TEXT NOT NULL,
 				SI_MFT_MODIFIED TEXT NOT NULL,
 				SI_ACCESSED TEXT NOT NULL,
			 	FN_CREATED TEXT NOT NULL,
 				FN_FILE_MODIFIED TEXT NOT NULL,
 				FN_MFT_MODIFIED TEXT NOT NULL,
				FN_ACCESSED TEXT NOT NULL,
				Parent_Dir_Name TEXT NOT NULL,
				Parent_SI_CREATED TEXT NOT NULL,
			 	Parent_FN_CREATED TEXT NOT NULL,
				Notes TEXT NOT NULL);'''

    cursor = sqliteConnection.cursor()
    print("--> Successfully Connected to SQLite")
    cursor.execute(sqlite_create_table_query)
    sqliteConnection.commit()
    print("--> SQLite Table Created")


except sqlite3.Error as error:
    print("--> Sqlite Table Already Exists", error)


##############################################################################

# Creates a Python TSK / IMG_INFO Object. Img_Info Is Built Into Python TSK.
# This Allows Us To Be Able To Work With The Forensic Image.
image1 = pytsk3.Img_Info(imageFile)

# We Need An Object That Will Give Us Access To The File System. This Opens The File System & Stores It As An Object In filesystemObject.
# FS_Info Takes Two Arguments: Our Image Object AND (Optional) The Offset To Where Our File System Begins On The Partition We Want To Examine.
filesystemObject1 = pytsk3.FS_Info(image1)

#######################################################################################
# This lets us access a specific file entry within a file system by path: 
# ---> fileobject = filesystemObject1.open("/$MFT")

# Note: A file entry can also be accessed based on its "inode":
# ---> file_entry = fs.open_meta(inode=15)
#######################################################################################

if suppliedinode:
	fileobject = filesystemObject1.open_meta(inode=int(suppliedinode))

# Name Doesn't Work If You Look Up By Inode. This Is Why We Have To Parse For The Name In One Of Our Above Functions.
#print ("File Name:",fileobject.info.name.name)
#print ("File Inode:",fileobject.info.meta.addr)
#print ("File Type:", fileobject.info.meta.type)

# istat ntfs-analysis-image.dd 35 | grep -i "Created\|File Modified\|MFT Modified\|Accessed"








# Important REGEX Notes!
# The Match Object Has Properties & Methods Used To Retrieve Information About The Search & The Result
# .string ---> RETURNS THE ORIGINAL STRING PASSED INTO THE FUNCTION
# .group() ---> RETURNS THE PART OF THE STRING WHERE THERE WAS A MATCH


# NOTE: Short File Names (file.txt) Only Has One $FILE_NAME Attribute. Long File Names (Using_UPX_as_a_security_packer.pdf) Will Have Two $FILE_NAME Attributes.
# Why Two? One For The Long File Name (Using_UPX_as_a_security_packer.pdf), And One For The DOS-Compatible Short Name (USING_~1.PDF)
# This Comes Into Play When We Are Parsing The Names With Regex Above In The returnTimetamps Function.


def returnTimetamps(imageFile, inode):

	# stdout=subprocess.PIPE Hides The Output of the Command So That It's Not Shown In The Terminal
	process = subprocess.run(["istat", imageFile, inode],check = True, stdout = subprocess.PIPE, universal_newlines = True)
	output = process.stdout
	#print(type(output))

# [:-6] Accounts For Deleting The Time Zone. The Time Zone Will Only Ever Be A Max 6 Characters and A Min Of 5. If It's 5, We Only Delete The Blank Space.
	matchCreated = re.findall("Created:.*\(.*\)", output)
	for i in range (0, len(matchCreated)):
		matchCreated[i] = matchCreated[i].replace("Created:","")[:-6].strip()
	
	matchFileModified = re.findall("File Modified:.*\(.*\)", output)
	for i in range (0, len(matchFileModified)):
		matchFileModified[i] = matchFileModified[i].replace("File Modified:","")[:-6].strip()
	
	matchMFTModified = re.findall("MFT Modified:.*\(.*\)", output)
	for i in range (0, len(matchMFTModified)):
		matchMFTModified[i] = matchMFTModified[i].replace("MFT Modified:","")[:-6].strip()
	
	matchAccessed = re.findall("Accessed:.*\(.*\)", output)
	for i in range (0, len(matchAccessed)):
		matchAccessed[i] = matchAccessed[i].replace("Accessed:","")[:-6].strip()
	

	#Parsing Out the File Names / Directory Names. I Have To Do It This Way, As You Can't Get The Name From Pytsk If You Are Supplying The Inode To Open The File
	matchFileName = re.findall("Name:.*", output)
	#print(matchFileName)
	for i in range(0, len(matchFileName)):
		matchFileName[i] = matchFileName[i].replace("Flags: Archive\n","").replace("Name: ","").strip()
	#print(matchFileName)
	
	#Parses Out The Parent File's Inode
	matchParentEntryinode = re.search("Parent MFT Entry:.*Sequence", output).group().replace("Parent MFT Entry:","").replace("Sequence","").strip()


	listsoflists = [matchCreated, matchFileModified, matchMFTModified, matchAccessed, matchFileName, matchParentEntryinode]
	
	return (listsoflists)



############################################################
#  TIMESTOMP CHECK 1 FUNCTION: DOES IT HAVE MILLISECONDS?  #
############################################################

def testone(allTimestamps):

	# ListofLists (AKA allTimestamps) Format: 
	# [Created[$SI,$FN,$FN], File_Modified[$SI,$FN,$FN], MFT_Modifiled[$SI,$FN,$FN], Accessed[$SI,$FN,$FN], File_Name[File_Name (for $Files & Dirs), File_Name (for Reg Files], matchParentEntryinode]
	# For Example, To Access The CREATED Date of $SI, You Would Do: allTimestamps[0][0]
	# For Example, To Access The Regular File's Name, You Would Do: allTimestamps[4][1]
	# For Example, To Access A Directory or $File's Name, You Would Do: allTimestamps[4][0]

	###########################
	#  $STANDARD_INFORMATION  #
	###########################

	SI_CREATED = allTimestamps[0][0]
	SI_FILE_MODIFIED = allTimestamps[1][0]
	SI_MFT_MODIFIED = allTimestamps[2][0]
	SI_ACCESSED = allTimestamps[3][0]

	################
	#  $FILE_NAME  #
	################

	FN_CREATED = allTimestamps[0][1]
	FN_FILE_MODIFIED = allTimestamps[1][1]
	FN_MFT_MODIFIED = allTimestamps[2][1]
	FN_ACCESSED = allTimestamps[3][1]


	# This Will Have 29 Characters:
	# 2012-07-14 15:40:46.775110600
	# Which Is A Normal, Legitimate Timestamp

	# This Holds The Number Of Timestamps That Have Less Than 29 Characters
	CHARACTER_COUNTER = 0
	# This Holds The Number Of Timestamps That Have ALL Zeros In Their Milliseconds
	TIMESTAMP_ALL_ZEROS = 0

	#Use A Dictionary Instead..? Then You Can Address Names.
	TIMESTAMP_DICT= { "SI_CREATED":SI_CREATED, 
		  	  "SI_FILE_MODIFIED" : SI_FILE_MODIFIED, 
		  	  "SI_MFT_MODIFIED" : SI_MFT_MODIFIED, 
		  	  "SI_ACCESSED" : SI_ACCESSED, 
		  	  "FN_CREATED" : FN_CREATED, 
		  	  "FN_FILE_MODIFIED" : FN_FILE_MODIFIED, 
		  	  "FN_MFT_MODIFIED" : FN_MFT_MODIFIED, 
		  	  "FN_ACCESSED" : FN_ACCESSED}
		  	  #"Travis Test" : "2012-07-14 15:40:46.000000600"}

	for timestamp in TIMESTAMP_DICT:
		character_count = 0
		for character in TIMESTAMP_DICT[timestamp]:
			character_count = character_count + 1
		if character_count < 29:
			CHARACTER_COUNTER = CHARACTER_COUNTER + 1
			print("-->", timestamp, "Has Less Than 29 Characters!")
		elif (character_count == 29) and (TIMESTAMP_DICT[timestamp][20] == str(0) and TIMESTAMP_DICT[timestamp][21] == str(0) and TIMESTAMP_DICT[timestamp][22] == str(0) and TIMESTAMP_DICT[timestamp][23] == str(0) and TIMESTAMP_DICT[timestamp][24] == str(0)):
			TIMESTAMP_ALL_ZEROS = TIMESTAMP_ALL_ZEROS + 1
			print("-->", timestamp, "Has Milliseconds That Are All Zeros!")
	
	print("--> THE NUMBER OF TIMESTAMPS WITH VALUES LESS THAN 29: ", CHARACTER_COUNTER)
	print("--> THE NUMBER OF TIMESTAMPS WITH MILLISECONDS BEING ALL ZEROS: ", TIMESTAMP_ALL_ZEROS, "\n")

	if CHARACTER_COUNTER == 0 and TIMESTAMP_ALL_ZEROS == 0:
		print ("--> No Anomalies Detected.")
		millisecondTest = "Pass"

	if CHARACTER_COUNTER != 0 or TIMESTAMP_ALL_ZEROS != 0:
		print ("--> Possible Timestomping Detected.")
		millisecondTest = "Fail"
	
	return(millisecondTest) #Printing 6 Things With This Function. Really We Only Need To Return millisecondTest, Containing "Pass" or "Fail"



######################################################################
#  TIMESTOMP CHECK 2: DO ANY $SI TIMESTAMPS PREDATE $FN TIMESTAMPS?  #
######################################################################

def testtwo(allTimestamps):

	# ListofLists (AKA allTimestamps) Format: 
	# [Created[$SI,$FN,$FN], File_Modified[$SI,$FN,$FN], MFT_Modifiled[$SI,$FN,$FN], Accessed[$SI,$FN,$FN], File_Name[File_Name (for $Files & Dirs), File_Name (for Reg Files], matchParentEntryinode]
	# For Example, To Access The CREATED Date of $SI, You Would Do: allTimestamps[0][0]
	# For Example, To Access The Regular File's Name, You Would Do: allTimestamps[4][1]
	# For Example, To Access A Directory or $File's Name, You Would Do: allTimestamps[4][0]

	###########################
	#  $STANDARD_INFORMATION  #
	###########################

	SI_CREATED = allTimestamps[0][0]
	SI_FILE_MODIFIED = allTimestamps[1][0]
	SI_MFT_MODIFIED = allTimestamps[2][0]
	SI_ACCESSED = allTimestamps[3][0]

	################
	#  $FILE_NAME  #
	################

	FN_CREATED = allTimestamps[0][1]
	FN_FILE_MODIFIED = allTimestamps[1][1]
	FN_MFT_MODIFIED = allTimestamps[2][1]
	FN_ACCESSED = allTimestamps[3][1]

	# The datetime Module Only Supports 6 Digits of Microseconds, Which Should Be Plenty. 
	# That Is Why We Have To Cut Off 3 Characters From The End With [:-3], Because Our Variables Currently Have 9 Millisecond Characters.

	# Issues Might Arise If The Timestamps Don't Have 000000's In Their Millisecond Collumn.

	SI_C_DateObject = datetime.datetime.strptime(SI_CREATED[:-3], "%Y-%m-%d %H:%M:%S.%f")
	SI_FM_DateObject = datetime.datetime.strptime(SI_FILE_MODIFIED[:-3], "%Y-%m-%d %H:%M:%S.%f")
	SI_MM_DateObject = datetime.datetime.strptime(SI_MFT_MODIFIED[:-3], "%Y-%m-%d %H:%M:%S.%f")
	SI_A_DateObject = datetime.datetime.strptime(SI_ACCESSED[:-3], "%Y-%m-%d %H:%M:%S.%f")

	FN_C_DateObject = datetime.datetime.strptime(FN_CREATED[:-3], "%Y-%m-%d %H:%M:%S.%f")
	FN_FM_DateObject = datetime.datetime.strptime(FN_FILE_MODIFIED[:-3], "%Y-%m-%d %H:%M:%S.%f")
	FN_MM_DateObject = datetime.datetime.strptime(FN_MFT_MODIFIED[:-3], "%Y-%m-%d %H:%M:%S.%f")
	FN_A_DateObject = datetime.datetime.strptime(FN_ACCESSED[:-3], "%Y-%m-%d %H:%M:%S.%f")

	# Less Than Means It's Earlier. Greater Means That It Happened At A Later Date.

	SI_DO = {"SI_CREATED" : SI_C_DateObject,
	 	 "SI_FILE_MODIFIED" : SI_FM_DateObject,
	 	 "SI_MFT_MODIFIED" : SI_MM_DateObject,
	 	 "SI_ACCESSED" : SI_A_DateObject}

	FN_DO = {"FN_CREATED" : FN_C_DateObject,
	 	 "FN_FILE_MODIFIED" : FN_FM_DateObject,
	 	 "FN_MFT_MODIFIED" : FN_MM_DateObject,
	 	 "FN_ACCESSED" : FN_A_DateObject}

	#FN_DO = [FN_C_DateObject, FN_FM_DateObject, FN_MM_DateObject, FN_A_DateObject]

	PREDATE_COUNTER = 0

	for EACH_SI_Entry in SI_DO:
		for EACH_FN_Entry in FN_DO:
			if SI_DO[EACH_SI_Entry] < FN_DO[EACH_FN_Entry]:
				print("-->", EACH_SI_Entry, SI_DO[EACH_SI_Entry], "Predates", EACH_FN_Entry, FN_DO[EACH_FN_Entry])
				PREDATE_COUNTER = PREDATE_COUNTER + 1

	print("--> Number of Predates:", PREDATE_COUNTER)

	if PREDATE_COUNTER > 0:
		print("\n--> Possible Timestomping Detected.")
		predateTest = "Fail"

	else:
		print("\n--> No Anomalies Detected.")
		predateTest = "Pass"

	# Using The .timestamp() Method Will Let Us Convert From Our Parsed String To Epoch Time.
	# %f Is For Microseconds. For Every Timetamp Formatting Code, Check Here: strftime.org.
	# This Method Only Supports 6 Digits of Microseconds, Which Should Be Plenty. 
	# Bigger Epoch Time = Newer, More Recent.

	#epochTime = datetime.datetime.strptime(SI_CREATED[:-3], "%Y-%m-%d %H:%M:%S.%f").timestamp()

	#print(epochTime)
	# The Output Looks Like This --> 1530274527.243865
	# So We Would Just Need To Compare That Number With Another Value And See Which One Is Bigger. Bigger = Newer, More Recent.

	# Using A Float, We Can Keep The Decimals.

	#Format That We Are Grabbing From the MFT: 2012-07-14 15:40:46.775110600
	# 2012-07-14 15:40:46.775110600

	
	# Return A List Containing The Test Result & All Date Objects
	resultlisttest2 = [predateTest, SI_C_DateObject, SI_FM_DateObject, SI_MM_DateObject, SI_A_DateObject, FN_C_DateObject, FN_FM_DateObject, FN_MM_DateObject, FN_A_DateObject]
	
	return(resultlisttest2) # Need To Return Print Statements??? Printing 3 Things With This Function.


#############################################################################################################
#  TIMESTOMP CHECK 3: MFT [METADATA] CHANGE TIME OF FILE IS EARLIER THAN PARENT FOLDER BIRTH/CREATION TIME  #
#############################################################################################################

def testthree(allTimestamps):
	
	# ListofLists Format: 
	# [Created[$SI,$FN,$FN], File_Modified[$SI,$FN,$FN], MFT_Modifiled[$SI,$FN,$FN], Accessed[$SI,$FN,$FN], File_Name[File_Name (for $Files & Dirs), File_Name (for Reg Files], matchParentEntryinode]
	# For Example, To Access The Parent's Inode, You Would Do: allTimestamps[5][0]

	# A File's MFT Change Time Should Not Be Earlier Than The Parent Folder's Birth / Creating Time.
	# A FILE CANNOT BE PLACED INTO A DIRECTORY THAT DOESN'T EXIST!

	# Example of What We're Matching:
	# Parent MFT Entry: 5 	Sequence: 5

	# Grabs Parent's inode Number
	parentsInode = allTimestamps[5]

	# Calls Function To Get Parent Information
	parentTimestamps = returnTimetamps(imageFile, parentsInode)

	if parentTimestamps[4][0] == ".":
		ParentDirectoryName = "/"
	
	elif parentTimestamps[4][1] and "~" in str(parentTimestamps[4][0]):
		ParentDirectoryName = "\"" + parentTimestamps[4][1] + "\""
	
	else:
		ParentDirectoryName = "\"" + parentTimestamps[4][0] + "\""

	#if str(fileobject.info.meta.type) == "TSK_FS_META_TYPE_REG":
	#	if "$" in allTimestamps[4][0]:
	#		matchFileName = allTimestamps[4][0]
	#		print("\n3.) Comparing Parent Directory Timestamps", "(\"",ParentDirectoryName, "\")", "To File Timestamps", "(\"", matchFileName, "\"):")
	
	#	else:
	#		matchFileName = allTimestamps[4][1]
	#		print("\n3.) Comparing Parent Directory Timestamps", "(\"",ParentDirectoryName, "\")", "To File Timestamps", "(\"", matchFileName, "\"):")

	#elif str(fileobject.info.meta.type) == "TSK_FS_META_TYPE_DIR":
	#	matchFileName = allTimestamps[4][0]
	#	print("\n3.) Comparing Parent Directory Timestamps", "(\"",ParentDirectoryName, "\")", "To File Timestamps", "(\"", matchFileName, "\"):")

	print("\n3.) Comparing Parent Directory Timestamps", "(\"",ParentDirectoryName, "\")", "To File Timestamps:")

	# allTimestamps Format: 
	# [Created[$SI,$FN,$FN], File_Modified[$SI,$FN,$FN], MFT_Modifiled[$SI,$FN,$FN], Accessed[$SI,$FN,$FN], File_Name[File_Name (for $Files & Dirs), File_Name (for Reg Files], matchParentEntryinode]
	# For Example, To Access The CREATED Date of $SI, You Would Do: allTimestamps[0][0]

	# File $SI MFT Modified
	SI_MFT = parentTimestamps[3][0]
	SI_MM_DateObject = datetime.datetime.strptime(SI_MFT[:-3], "%Y-%m-%d %H:%M:%S.%f")

	# File $FN MFT Modified
	FN_MFT = parentTimestamps[3][1]
	FN_MM_DateObject = datetime.datetime.strptime(FN_MFT[:-3], "%Y-%m-%d %H:%M:%S.%f")
	
	# Parent Directory #SI Creation Date
	PARENT_SI_CREATED = parentTimestamps[0][0]
	PARENT_SI_C_DateObject = datetime.datetime.strptime(PARENT_SI_CREATED[:-3], "%Y-%m-%d %H:%M:%S.%f")

	# Parent Directory #FN Creation Date
	PARENT_FN_CREATED = parentTimestamps[0][1]
	PARENT_FN_C_DateObject = datetime.datetime.strptime(PARENT_FN_CREATED[:-3], "%Y-%m-%d %H:%M:%S.%f")


	if (PARENT_SI_C_DateObject < SI_MM_DateObject) or (PARENT_SI_C_DateObject < FN_MM_DateObject) or (PARENT_FN_C_DateObject < SI_MM_DateObject) or (PARENT_FN_C_DateObject < FN_MM_DateObject):
		#print("")
		print("\n--> Possible Timestomping Detected.\n")
		parentTest = "Fail"

	else:
		print("\n--> No Anomalies Detected.\n")
		parentTest = "Pass"
		print("hi")
	
	# Return A List Containing The Test Result, Parent Directory Name, & Parent Date Objects
	resultlisttest3 = [parentTest, ParentDirectoryName, PARENT_SI_C_DateObject, PARENT_FN_C_DateObject]

	return(resultlisttest3) #Printing 1 Other Thing With This Function. If I Want to Include That.. I Need To Pass It.


####################################################################################################################################
#  TIMESTOMP CHECK 4: CHECK MEMORY FOR TRACES OF TIMESTOMP.EXE or SETMACE.EXE (IF MEMORY FILE IS SUPPLIED & -memdump FLAG IS USED  #
####################################################################################################################################

# This Only Needs To Be Called Once, Even When Looping Through The Entire Image

def memorySearch():

	print("4.) Performing Memory Analysis For Timestamp Manipulation Programs:\n")

	#malicious_processes = ["Timestomp.exe", "SetMace.exe"]

	TimeStompCounter = 0
	SetMaceCounter = 0

	# Each Item In The List Is A Volatility Command & Will Be Fed Into The Subprocess For Execution
	commandsList = ["pslist", "cmdscan", "consoles", "shimcache"]#, "mftparser"]

	# Example of What We're Dealing With
	#Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86

	# If Profile Flag Is Provided, Just Use That One.
	if args.profile:
		print("\n--> Checking For Malicious Processes With Supplied Profile:", args.profile)
		for command in commandsList:
				profile = "--profile=" + args.profile
				process = subprocess.run(["volatility", "-f", memoryFile, profile, command],check = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE, universal_newlines = True)
				commandOutput = process.stdout

				if "Timestomp.exe" in commandOutput:
					TimeStompCounter = TimeStompCounter + 1
					print ("--> Timestomp.exe Detected In", command, "results!")

				if "SetMace.exe" in commandOutput:
					SetMaceCounter = SetMaceCounter + 1
					print ("--> SetMace.exe Detected In", command, "results!")

	# If Profile Flag Is NOT Provided, Try All Of Them.
	else:
	
		# stdout=subprocess.PIPE Hides The Output of the Command So That It's Not Shown In The Terminal
		process = subprocess.run(["volatility", "-f", memoryFile, "imageinfo"],check = True, stdout = subprocess.PIPE, universal_newlines = True)
		output = process.stdout

		matchProfiles = re.search("Suggested Profile\(s\) :.*", output)

		profileGroup = matchProfiles.group().replace("Suggested Profile(s) : ","").strip().split(", ")
		#print(profileGroup)
		
		print("\n--> No Profile Supplied, Checking Against All Suggested Profiles...")
		for profile in profileGroup:
			memoryNotes = ""
			print("--> Checking For Malicious Processes With Profile", profile)
			profile = "--profile=" + profile
	
			for command in commandsList:
				process = subprocess.run(["volatility", "-f", memoryFile, profile, command],check = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE, universal_newlines = True)
				commandOutput = process.stdout

				if "Timestomp.exe" in commandOutput:
					TimeStompCounter = TimeStompCounter + 1
					print ("--> Timestomp.exe Detected In", command, "results!")

				if "SetMace.exe" in commandOutput:
					SetMaceCounter = SetMaceCounter + 1
					print ("--> SetMace.exe Detected In", command, "results!")

	
	memoryNotes = ""
	if TimeStompCounter > 0:
		print("\n--> Timestop.exe Detected\n")
		memoryNotes = memoryNotes + "# Timestop.exe Detected #"

	if SetMaceCounter > 0:
		print("\n--> SetMace.exe Detected\n")
		memoryNotes = memoryNotes + "# SetMace.exe Detected #"

	else:
		print("\n--> No Evidence of Malicious Processes\n")
		memoryNotes = "# No Evidence of Malicious Processes #"


	return(memoryNotes)

###################################
#  Insert Into Database Function  #
###################################

def databaseinsert(matchFileName, fileType, millisecondTest, predateTest, parentTest, SI_C_DateObject, SI_FM_DateObject, SI_MM_DateObject, SI_A_DateObject, FN_C_DateObject, FN_FM_DateObject, FN_MM_DateObject, FN_A_DateObject, ParentDirectoryName, PARENT_SI_C_DateObject, PARENT_FN_C_DateObject, memoryNotes):

	try:
		cursor.execute("INSERT INTO TIMESTOMP_FINDINGS (Name, File_Type, Millisecond_Test, Predate_Test, Parent_Directory_Test, SI_CREATED, SI_FILE_MODIFIED, SI_MFT_MODIFIED, SI_ACCESSED, FN_CREATED, 	FN_FILE_MODIFIED, FN_MFT_MODIFIED, FN_ACCESSED, Parent_Dir_Name, Parent_SI_CREATED, Parent_FN_CREATED, Notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (matchFileName, fileType, millisecondTest, predateTest, parentTest, SI_C_DateObject, SI_FM_DateObject, SI_MM_DateObject, SI_A_DateObject, FN_C_DateObject, FN_FM_DateObject, FN_MM_DateObject, FN_A_DateObject, ParentDirectoryName, PARENT_SI_C_DateObject, PARENT_FN_C_DateObject, memoryNotes))
		sqliteConnection.commit()
		print("Record Inserted Successfully Into TIMESTOMP_FINDINGS")
		#cursor.close()

	except sqlite3.Error as error:
		print("Record Already Exists In Database Timestomp_Findings_Database...", error)

##################################
#  Directory Recursion Function  #
##################################

def directoryRecurse(directoryObject, parentPath, memory_search_counter, memoryNotes):

	for eachObject in directoryObject:

		# If there is no type, then they are unallocated or deleted. Unallocated  entries don't have an info.meta member OR the info.name.flags member has TSK_FS_NAME_FLAG_UNALLOC set.
		if eachObject.info.name.flags == pytsk3.TSK_FS_NAME_FLAG_UNALLOC or eachObject.info.meta.type == None :
			#print("No Meta or Unalloc")
			continue

		# If our directory entry has . or .. as a file name we will skip it by using continue. (Continue skips the rest of the code and continues with the next iteration.)
		# . and .. are special directory entries that allow us to be able to refer to the directory itself (.) and the parent directory (..). 
		# If we were to keep calling the parent of itself, we could enter into an infinite loop of going back into the same directory. [& This happened to me.]

		#The b specifies a bytes object.
		if eachObject.info.name.name == b"." or eachObject.info.name.name == b"..":
			#print(". or .. Detected & Skipped!")
			continue

		# If the contents of eachObject.info.meta.type are TSK_FS_META_TYPE_DIR then the directory entry is a directory.
		# If the directory entry is a directory, we need to recurse and find the files within the directory.

		if eachObject.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
			# The as_directory function which will return a directory object if the file object it is launched from is in fact a directory. The function will error out if not.
			sub_directory = eachObject.as_directory()
			#print (sub_directory)
			#print(eachObject.info.name.name)
			parentPath.append(eachObject.info.name.name)
			#print(parentPath)

			# Calls Itself
			directoryRecurse(sub_directory,parentPath, memory_search_counter, memoryNotes)
			# Pop(-1_ means to remove the last element that was added to the list.
			parentPath.pop(-1)
			#print ("Directory: %s" % filepath)



			# File Type For Database Entry
			fileType = "Directory"

			# Returns inode Number
			fileinode = str(eachObject.info.meta.addr)
		
			# Returns All Timestamps
			allTimestamps = returnTimetamps(imageFile, fileinode)

			# File Name:
			matchFileName = str(eachObject.info.name.name).replace("b'","").replace("'","")

			##############
			#  TEST ONE  #
			##############
			print("---------------------------------------------------")
			print("1.) Checking Timestamps For Millisecond Values For Directory:", "(\"", matchFileName,"\"):", "\n")

			testoneresultsstring = testone(allTimestamps)
			# testoneresultslist[0] Is A String "Pass" or "Fail"
			millisecondTest = testoneresultsstring

			##############
			#  TEST TWO  #
			##############

			print("\n2.) Checking If Any $SI Timestamps Predate $FN Timestamps For Directory:","(\"", matchFileName,"\"):", "\n")

			testtworesultslist = testtwo(allTimestamps)
			# testtworesultslist[0] Is A String "Pass" or "Fail"
			predateTest = testtworesultslist[0]

			SI_C_DateObject = testtworesultslist[1]
			SI_FM_DateObject = testtworesultslist[2]
			SI_MM_DateObject = testtworesultslist[3]
			SI_A_DateObject = testtworesultslist[4]

			FN_C_DateObject = testtworesultslist[5]
			FN_FM_DateObject = testtworesultslist[6]
			FN_MM_DateObject = testtworesultslist[7]
			FN_A_DateObject = testtworesultslist[8]

			################
			#  TEST THREE  #
			################

			testthreeresultslist = testthree(allTimestamps)
			# testthreeresultslist[0] Is A String "Pass" or "Fail"
			parentTest = testthreeresultslist[0]

			# testthreeresultslist[1] Contains The Name Of The Parent Directory
			ParentDirectoryName = testthreeresultslist[1]

			#print("\n3.) Comparing Parent Directory Timestamps", "(\"",ParentDirectoryName, "\")", "To File Timestamps", "(\"", matchFileName, "\"):")
			print("---------------------------------------------------")
			PARENT_SI_C_DateObject = testthreeresultslist[2]
			PARENT_FN_C_DateObject = testthreeresultslist[3]

			memory_search_counter = memory_search_counter + 1
			
			if args.memdump and memory_search_counter == 1:
				memoryNotes = memorySearch()

			if not args.memdump: 
				memoryNotes = "# Memory Analysis Not Performed #"

			databaseinsert(matchFileName, fileType, millisecondTest, predateTest, parentTest, SI_C_DateObject, SI_FM_DateObject, SI_MM_DateObject, SI_A_DateObject, FN_C_DateObject, FN_FM_DateObject, FN_MM_DateObject, FN_A_DateObject, ParentDirectoryName, PARENT_SI_C_DateObject, PARENT_FN_C_DateObject, memoryNotes)



		elif eachObject.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG and eachObject.info.meta.size != 0:		

			# File Type For Database Entry
			fileType = "File"

			# Returns inode Number
			fileinode = str(eachObject.info.meta.addr)
		
			# Returns All Timestamps
			allTimestamps = returnTimetamps(imageFile, fileinode)

			# File Name:
			matchFileName = str(eachObject.info.name.name).replace("b'","").replace("'","")

			##############
			#  TEST ONE  #
			##############
			print("---------------------------------------------------")
			print("1.) Checking Timestamps For Millisecond Values For File:", "(\"", matchFileName,"\"):", "\n")

			testoneresultsstring = testone(allTimestamps)
			# testoneresultslist Is A String "Pass" or "Fail"
			millisecondTest = testoneresultsstring

			##############
			#  TEST TWO  #
			##############

			print("\n2.) Checking If Any $SI Timestamps Predate $FN Timestamps For File:","(\"", matchFileName,"\"):", "\n")

			testtworesultslist = testtwo(allTimestamps)
			# testtworesultslist[0] Is A String "Pass" or "Fail"
			predateTest = testtworesultslist[0]

			SI_C_DateObject = testtworesultslist[1]
			SI_FM_DateObject = testtworesultslist[2]
			SI_MM_DateObject = testtworesultslist[3]
			SI_A_DateObject = testtworesultslist[4]

			FN_C_DateObject = testtworesultslist[5]
			FN_FM_DateObject = testtworesultslist[6]
			FN_MM_DateObject = testtworesultslist[7]
			FN_A_DateObject = testtworesultslist[8]

			################
			#  TEST THREE  #
			################

			testthreeresultslist = testthree(allTimestamps)
			# testthreeresultslist[0] Is A String "Pass" or "Fail"
			parentTest = testthreeresultslist[0]

			# testthreeresultslist[1] Contains The Name Of The Parent Directory
			ParentDirectoryName = testthreeresultslist[1]

			#print("\n3.) Comparing Parent Directory Timestamps", "(\"",ParentDirectoryName, "\")", "To File Timestamps", "(\"", matchFileName, "\"):")
			print("---------------------------------------------------")
			PARENT_SI_C_DateObject = testthreeresultslist[2]
			PARENT_FN_C_DateObject = testthreeresultslist[3]

			memory_search_counter = memory_search_counter + 1
			
			if args.memdump and memory_search_counter == 1:
				memoryNotes = memorySearch()

			if not args.memdump: 
				memoryNotes = "# Memory Analysis Not Performed #"
			
			databaseinsert(matchFileName, fileType, millisecondTest, predateTest, parentTest, SI_C_DateObject, SI_FM_DateObject, SI_MM_DateObject, SI_A_DateObject, FN_C_DateObject, FN_FM_DateObject, FN_MM_DateObject, FN_A_DateObject, ParentDirectoryName, PARENT_SI_C_DateObject, PARENT_FN_C_DateObject, memoryNotes)
			




#####################################################
#  ACTUAL FUNCTION CALLING / EXECUTING THE PROGRAM  #
#####################################################

if args.scanall == True:
	
	memory_search_counter = 0
	memoryNotes = ""
	directoryObject1 = filesystemObject1.open_dir(path="/")
	directoryRecurse(directoryObject1, [], memory_search_counter, memoryNotes)

elif args.inode:

	# Returns All Timestamps
	allTimestamps = returnTimetamps(imageFile, suppliedinode)

	# allTimestamps Format: 
	# [Created[$SI,$FN,$FN], File_Modified[$SI,$FN,$FN], MFT_Modifiled[$SI,$FN,$FN], Accessed[$SI,$FN,$FN], File_Name[File_Name (for $Files & Dirs), File_Name (for Reg Files], matchParentEntryinode]
	# For Example, To Access The CREATED Date of $SI, You Would Do: allTimestamps[0][0]

	print("\n$STANDARD_INFORMATION")
	print("CREATED: ", allTimestamps[0][0])
	print("FILE MODIFIED: ", allTimestamps[1][0])
	print("MFT MODIFIED: ", allTimestamps[2][0])
	print("ACCESSED: ", allTimestamps[3][0])

	print("--------------------------------------------")

	print("$FILE_NAME")
	print("CREATED: ", allTimestamps[0][1])
	print("MODIFIED: ", allTimestamps[1][1])
	print("MFT MODIFIED: ", allTimestamps[2][1])
	print("ACCESSED: ", allTimestamps[3][1])

	# Determine File Type & File Name For Database Entry
	
	if str(fileobject.info.meta.type) == "TSK_FS_META_TYPE_REG":
		fileType = "File"
		
		#HITTING BOTH IFS ON SOME FILES
		if "~" in str(allTimestamps[4][0]):
			matchFileName = allTimestamps[4][1]
			#print("YELLLOW")
			
		elif "~" in str(allTimestamps[4][1]):
			matchFileName = allTimestamps[4][0]
			#print("REDD")
		
		elif "$" in str(allTimestamps[4][1]):
			matchFileName = allTimestamps[4][0]
			#print("ORANGE")

		else:
			matchFileName = allTimestamps[4][0]
			#print("BACON")
			
	elif str(fileobject.info.meta.type) == "TSK_FS_META_TYPE_DIR":
		fileType = "Directory"
		matchFileName = allTimestamps[4][0]
		#print("GREEN")
	
	elif str(fileobject.info.meta.type) != "TSK_FS_META_TYPE_DIR" and str(fileobject.info.meta.type) != "TSK_FS_META_TYPE_REG":
		matchFileName = allTimestamps[4][0]
		#print("PURPLE")

	
	##############
	#  TEST ONE  #
	##############

	if fileType == "File":
		print("\n1.) Checking Timestamps For Millisecond Values For File:", "(\"", matchFileName,"\"):", "\n")

	elif fileType == "Directory":
		print("\n1.) Checking Timestamps For Millisecond Values For Directory:", "(\"", matchFileName,"\"):", "\n")

	testoneresultstring = testone(allTimestamps)
	# testoneresultslist[0] Is A String "Pass" or "Fail"
	millisecondTest = testoneresultstring

	##############
	#  TEST TWO  #
	##############

	if fileType == "File":
		print("\n2.) Checking If Any $SI Timestamps Predate $FN Timestamps For File:", "(\"", matchFileName,"\"):", "\n")

	elif fileType == "Directory":
		print("\n2.) Checking If Any $SI Timestamps Predate $FN Timestamps For Directory:", "(\"", matchFileName,"\"):", "\n")

	testtworesultslist = testtwo(allTimestamps)
	# testtworesultslist[0] Is A String "Pass" or "Fail"
	predateTest = testtworesultslist[0]

	SI_C_DateObject = testtworesultslist[1]
	SI_FM_DateObject = testtworesultslist[2]
	SI_MM_DateObject = testtworesultslist[3]
	SI_A_DateObject = testtworesultslist[4]

	FN_C_DateObject = testtworesultslist[5]
	FN_FM_DateObject = testtworesultslist[6]
	FN_MM_DateObject = testtworesultslist[7]
	FN_A_DateObject = testtworesultslist[8]

	################
	#  TEST THREE  #
	################

	testthreeresultslist = testthree(allTimestamps)
	# testthreeresultslist[0] Is A String "Pass" or "Fail"
	parentTest = testthreeresultslist[0]

	# testthreeresultslist[1] Contains The Name Of The Parent Directory
	ParentDirectoryName = testthreeresultslist[1]

	#print("\n3.) Comparing Parent Directory Timestamps", "(\"",ParentDirectoryName, "\")", "To File Timestamps", "(\"", matchFileName, "\"):")

	PARENT_SI_C_DateObject = testthreeresultslist[2]
	PARENT_FN_C_DateObject = testthreeresultslist[3]

	###############
	#  TEST FOUR  #
	###############
	
	if args.memdump:
		memoryNotes = memorySearch()
	else: 
		memoryNotes = "# Memory Analysis Not Performed #"

	databaseinsert(matchFileName, fileType, millisecondTest, predateTest, parentTest, SI_C_DateObject, SI_FM_DateObject, SI_MM_DateObject, SI_A_DateObject, FN_C_DateObject, FN_FM_DateObject, FN_MM_DateObject, FN_A_DateObject, ParentDirectoryName, PARENT_SI_C_DateObject, PARENT_FN_C_DateObject, memoryNotes)



############################
#  CREATING A .CSV REPORT  #
############################

# Python3 - You Can't Open A Text File As Binary ("w" VS "wb")

data = cursor.execute("SELECT * FROM TIMESTOMP_FINDINGS")

with open("myReport.csv", "w") as exportReport:
	writer = csv.writer(exportReport)
	writer.writerow(["File Name", 
			 "File Type", 
			 "Has Milliseconds", 
			 "$SI Predates $FN Test",
			 "File MFT Change Time < Parent Creation Time",
 			 "$SI Creation", 
			 "$SI File Modified",
			 "$SI MFT Modified",
			 "$SI Accessed",
 			 "$FN Creation", 
			 "$FN File Modified",
			 "$FN MFT Modified",
			 "$FN Accessed",
			 "Parent Directory",
			 "Parent $SI Creation", 
 			 "Parent $FN Creation", 
			 "Memory Results"], )
	writer.writerows(data)
	print("Report Exported")

#######################################
# Close SQLite Connection
#######################################

if (sqliteConnection):
	cursor.close()
	sqliteConnection.close()
	print("The SQLite Connection Has Been Closed!")
