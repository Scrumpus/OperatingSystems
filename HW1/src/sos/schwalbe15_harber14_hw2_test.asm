#Below is pidgin code to trigger an illegal instruction interrupt
SET R0 56
SET R1 12 # Set the location to save to in next instruction
SAVE R0 R1 #should trigger illegal instruction interrupt

########################
# Below is Pidgin code to test an illegal memory access interrupt
# Uncomment the instructions below to run this test (make sure to
# commont the three instructions above, first, however.)
#########################
#SET R0 0
#SET R1 5
#SET R2 5000
#SAVE R0 R2 #should trigger memory out of bounds interrupt
#SET R1 10 #should not be executed since interrupt will issue exit system call
##########################
