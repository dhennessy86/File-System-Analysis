#!/bin/bash

#########################################################
#	Date Created: 17th April 2017		                    	#
#	Date Last Modified: 25th April 2017               		#
#	Purpose: File System Analysis			                    #
#						                                          	#
#########################################################
#						                                          	
#	Exit Status:					                                
#							
#	exit 0 - Successfull completion of script	
#	exit 1 - Required Arguments not supplied	
#	exit 2 - Target Image doesn't exist		
#	exit 3 - Target Image cannot be read		
#	exit 4 - Keyword File doesn't exist		
#	exit 5 - Keyword File cannot be read		
#	exit 6 - Output File contains Information	
#							
#########################################################
#							
#	Declare & Check Agruments			
#							
#########################################################

# Declare arguments as variables
Target_Image=$1   		# targets image file
Keyword_File=$2	 		# keyword file to search for suspicious names
Output_File=$3			# Output report file 

# Test if the 3 arguments were supplied
if [[ -z $Target_Image || -z $Keyword_File || -z $Output_File ]]
then
	echo "+++ Command line argument's not defined"
	echo "+++ Usage $0 <target_image> <Keyword_File> <Output  Filename>"
	exit 1
fi


# Test if Target_File exists
if [ -e "$Target_Image" ]
then
	echo "+++ ${Target_Image} exists"
else
	echo "+++ ${Target_Image} doesnt exist"
	exit 2
fi

# Test if Target_Image is readable
if [ -r "$Target_Image" ]
then
	echo "+++ ${Target_Image} is readable"
else
	echo "+++ ${Target_Image}  is not readable"
	exit 3
fi

# Test if Keyword_File exists
if [ -e "$Keyword_File" ]
then
	echo "+++ ${Keyword_File} exists"
else
	echo "+++ ${Keyword_File} doesnt exist"
	exit 4
fi

# Test if Keyword_File is readable
if [ -r "$Keyword_File" ]
then
	echo "+++ ${Keyword_File} is readable"
else
	echo "+++ ${Keyword_File}  is not readable"
	exit 5
fi

# Test if Output_File contains information
if [ -s "$Output_File" ]
then
	echo "+++ ${Output_File} contains information"
	exit 6
else
	echo "+++ ${Output_File} is blank"
fi

#########################################################
#							
#	MAIN CODE					
#							
#########################################################

# Start outputting data to the report file
echo "+++ Analsying ${Target_Image} +++ "
#Output the name of the image being analysed
echo "Image File: ${Target_Image}" > $Output_File  
#output username
echo "Username: $(whoami)" >> $Output_File  
#output date & time
echo "Date: $(date)" >> $Output_File  
echo >> $Output_File
echo "IMAGE INFORMATION" >> $Output_File  
echo >> $Output_File
# output the md5sum of the target file only
echo "MD5 Sum: $( md5sum ${Target_Image} | cut -c 1-32)" >> $Output_File

# Next check the amount of partitions on the Target File
# Number of partitions
Parts=$( fdisk -l ${Target_Image} | egrep "^${Target_Image}" | wc -l )
echo "# Parts: ${Parts}" >> $Output_File

echo "-------------------------------------" >> $Output_File

# run the main code for total number of partitions
x=1
while [ $x -le $Parts ]
do
	echo "Partition $x" >> $Output_File
	echo >> $Output_File
	# Output Start of Sector
	Start_Sector=$( fdisk -l ${Target_Image} | egrep -m1 "^${Target_Image}${x}" | awk '{print$2}' ) 
	echo "Start: ${Start_Sector}" >> $Output_File

	End_Sector=$( fdisk -l ${Target_Image} | egrep -m1 "^${Target_Image}${x}" | awk '{print$3}' )
	# Output End of Sector
	echo "End: ${End_Sector} " >> $Output_File

	# Output Length of Sector
	Length_Sector=$( fdisk -l ${Target_Image} | egrep -m1 "^${Target_Image}${x}" | awk '{print$4}' )
	echo "Length: ${Length_Sector}" >> $Output_File

	# Output Partition type from partition table
	echo "Partition Type (as reported in Partition Table): $( mmls -a ${Target_Image}  | grep ${Start_Sector} | tr -s '[:space:]' | cut -d ' ' -f 6 )" >> $Output_File

	# Output Partition type reported from file system analysis
	echo "Partition Type (as reported by File System Analysis): $( fsstat -o ${Start_Sector} ${Target_Image} | egrep -a "File System Type:" | sed 's/File System Type: //g')" >> $Output_File

	# output the partitions hash in md5 type
	# calculate the block size normally 512
	block_size=$( fdisk -l ${Target_Image} | egrep "Sector size" | egrep -m1 -o "[0-9]{3,}" | uniq )
	#i=$(( End_Sector - Start_Sector + 1 ))
	dd if=${Target_Image} of=Partition.dd bs=${block_size} skip=${Start_Sector} count=${Length_Sector} status=none
	HASH=$(md5sum Partition.dd | cut -c 1-32 ) 
	echo "Partition MD5: $HASH" >> $Output_File 
	#delete partition
	rm Partition.dd
	echo >> $Output_File
	echo "SUSPICIOUS FILES (Partition ${x})" >> $Output_File
	echo >> $Output_File
	# start loop to check for suspicious files

	cat $Keyword_File | while read line ; do fls -r -o $Start_Sector $Target_Image | egrep $line | sed 's/\+ r\/r //g;s/\*//g;s/\://g' | tr -d ' ' | tr '\t' ' ' ; done | sort -k1 | awk '{print$2" "$1}' >> $Output_File 

	echo >> $Output_File
	echo "ALL FILES (Partition ${x})" >> $Output_File
	echo >> $Output_File
	echo "Filename,Inode,MD5,File Information" >> $Output_File
	#Output all files
	echo "$(fls -r -o ${Start_Sector} ${Target_Image} | grep -v ".*$.*" | grep -v ".*OrphanFile.*" | tr -d '+r/*d' | tr -d ' ' | tr '\t' ' ' | sed 's/^-//g' | awk '{if(! a[$1]){print; a[$1]++}}' | while read i ; do echo $(echo $i | awk '{print$2","$1","}' | sed 's/:,/,/g' | tr -d [:space:] && echo ${i} | awk -F ':' '{print$1}' | while read a ; do icat -o ${Start_Sector} ${Target_Image} $a | md5sum | tr -d ' ' | cut -c 1-32 ; done | tr -d [:space:] && echo "," ; echo ${i} | awk -F ':' '{print$1}' | while read b ; do icat -o ${Start_Sector} ${Target_Image} $b | file - | awk -F: '{print$2}' | sed 's/^ //g' ; done ) ; done )" >> $Output_File
	echo "-------------------------------------" >> $Output_File

	x=$((x+1))  # increment the counter for number of partitions
done

#delete last line
sed -i '$ d' output

#output info to the user
echo
echo "Analysis of ${Target_Image} Complete!"
echo "Generating ${Output_File}......"
echo "Exiting...."

exit 0
