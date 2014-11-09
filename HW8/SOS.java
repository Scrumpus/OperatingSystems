
package sos;

import java.util.Collections;
import java.util.ListIterator;
import java.util.Random;
import java.util.Vector;


/**
* This class contains the simulated operating system (SOS). Realistically it
* would run on the same processor (CPU) that it is managing but instead it uses
* the real-world processor in order to allow a focus on the essentials of
* operating system design using a high level programming language.
*
*/

public class SOS implements CPU.TrapHandler
{
// ======================================================================
// Member variables
// ----------------------------------------------------------------------

/**
* This flag causes the SOS to print lots of potentially helpful status
* messages
**/
public static final boolean m_verbose = true;

/**
* The CPU the operating system is managing.
**/
private CPU m_CPU = null;

/**
* The RAM attached to the CPU.
**/
private RAM m_RAM = null;

/**
* A reference to the PCB which contains the current process
*/
private ProcessControlBlock m_currProcess;

/**
* Vector of devices installed on the computer
*/
private Vector<DeviceInfo> m_devices;

/**
* Vector of all available programs on the OS
*/
private Vector<Program> m_programs = new Vector<Program>();

/**
 * list of free blocks of RAM
 */
private Vector<MemBlock> m_freeList = new Vector<MemBlock>();


/**
* Specifies process ID for next process loaded. Should be incremented every time used
*/
private int m_nextProcessID = 1001;

/**
* A list of all currently loaded processes in states Ready, Running or Blocked
*/
private Vector<ProcessControlBlock> m_processes = new Vector<ProcessControlBlock>();

/**
 * A pointer to the MMU used by this CPU
 */
private MMU m_MMU;

//keeps track of when the CPU last called an interrupt
private double lastInterrupt = 0;


/*
* ======================================================================
* Constructors & Debugging
* ----------------------------------------------------------------------
*/

// These constants define the system calls this OS can currently handle
public static final int SYSCALL_EXIT = 0; /* exit the current program */
public static final int SYSCALL_OUTPUT = 1; /* outputs a number */
public static final int SYSCALL_GETPID = 2; /* get current process id */
public static final int SYSCALL_OPEN = 3; /* access a device */
public static final int SYSCALL_CLOSE = 4; /* release a device */
public static final int SYSCALL_READ = 5; /* get input from device */
public static final int SYSCALL_WRITE = 6; /* send output to device */
public static final int SYSCALL_EXEC = 7; /* spawn a new process */
public static final int SYSCALL_YIELD = 8; /* yield the CPU to another process */
public static final int SYSCALL_COREDUMP = 9; /* print process state and exit */


public static final int SYSTEM_HANDLER_SUCCESS = 0;
public static final int DEVICE_NOT_FOUND_ERROR = -1;
public static final int DEVICE_NOT_SHARABLE_ERROR = -2;
public static final int DEVICE_ALREADY_OPEN_ERROR = -3;
public static final int DEVICE_NOT_OPEN_ERROR = -4;
public static final int DEVICE_READ_ONLY_ERROR = -5;
public static final int DEVICE_WRITE_ONLY_ERROR = -6;
/**This process is used as the idle process' id*/
public static final int IDLE_PROC_ID = 999;

//minimum running time of a process
public static final double MIN_RUN_TIME = 25;

/**
* The constructor does nothing special
*/
public SOS(CPU c, RAM r, MMU m)
{
	// Init member list
	m_CPU = c;
	m_RAM = r;
	m_MMU = m;
	m_CPU.registerTrapHandler(this);
	m_currProcess = null;
	m_devices = new Vector<DeviceInfo>(0);
	initPageTable();
	int numPages = m_MMU.getNumPages();
	m_freeList.add(new MemBlock(numPages,m_MMU.getSize()-numPages));
	
}// SOS ctor

/**
* Does a System.out.print as long as m_verbose is true
**/
public static void debugPrint(String s)
{
	if (m_verbose)
	{
		System.out.print(s);
	}
}

/**
* Does a System.out.println as long as m_verbose is true
**/
public static void debugPrintln(String s)
{
	if (m_verbose)
	{
		System.out.println(s);
	}
}




/**
* getDeviceInfo
*
* Finds a device's information from within the m_devices vector
*
* @param id of the device
* @return the DeviceInfo object of the device
*/
private DeviceInfo getDeviceInfo(int id)
{
	for(DeviceInfo device : m_devices)
		if(device.getId() == id)
			return device;
	return null;

}//getDeviceInfo

/**
 * toPageSizeMultiple
 * 
 * converts a desired process size to a multiple of 
 * the MMU page size
 */
private int toPageSizeMultiple(int size)
{
	//make sure size is a multiple of the page size
    if (size%m_MMU.getPageSize() != 0)
    {
  	  size += (m_MMU.getPageSize() - size%m_MMU.getPageSize());
    }
    
    return size;
}

/**
 * Helper method that gets the amount of free space left in RAM
 */

private int getFreeSpace()
{
	int total = 0;
	for (MemBlock fb:m_freeList)
	{
		total = total + fb.getSize();
	}
	return total;
}



/**
 * Helper method to merge two free blocks of memory
 */
public void merge(MemBlock block1, MemBlock block2)
{
	
	if (!isAdjacent(block1,block2))
	{
		System.out.println("Failed merge: two blocks not adjacent.");
		return;
	}
	
	int addr1 = block1.getAddr();
	int addr2 = block2.getAddr();
	int size1 = block1.getSize();
	int size2 = block2.getSize();
	
	int newSize = size1 + size2;
	int newAddr;
	
	//get new address
	if (addr1 <= addr2)
	{
		newAddr = addr1;
	}
	else 
	{
		newAddr = addr2;
	}
	
	MemBlock mergedBlock = new MemBlock(newAddr,newSize);
	m_freeList.remove(block1);
	m_freeList.remove(block2);
	m_freeList.add(mergedBlock);
	return;
}

/**
 * Check if two blocks are adjacent
 */
public boolean isAdjacent(MemBlock block1, MemBlock block2)
{
	int addr1 = block1.getAddr();
	int addr2 = block2.getAddr();
	int lim1 = addr1 + block1.getSize();
	int lim2 = addr2 + block2.getSize();
	
	//return true if either base address is the same as the other's physical limit address
	return (addr1 == lim2 || addr2 == lim1);
	
}

    

/*
* ======================================================================
* Process Management Methods
* ----------------------------------------------------------------------
*/
    
    /**
* selectBlockedProcess
*
* select a process to unblock that might be waiting to perform a given
* action on a given device. This is a helper method for system calls
* and interrupts that deal with devices.
*
* @param dev the Device that the process must be waiting for
* @param op the operation that the process wants to perform on the
* device. Use the SYSCALL constants for this value.
* @param addr the address the process is reading from. If the
* operation is a Write or Open then this value can be
* anything
*
* @return the process to unblock -OR- null if none match the given criteria
*/
    public ProcessControlBlock selectBlockedProcess(Device dev, int op, int addr)
    {
        ProcessControlBlock selected = null;
        for(ProcessControlBlock pi : m_processes)
        {
            if (pi.isBlockedForDevice(dev, op, addr))
            {
                selected = pi;
                break;
            }
        }//for

        return selected;
    }//selectBlockedProcess
    
    
    /**
* createIdleProcess
*
* creates a one instruction process that immediately exits. This is used
* to buy time until device I/O completes and unblocks a legitimate
* process.
*
*/
    public void createIdleProcess()
    {
        int progArr[] = { 0, 0, 0, 0, //SET r0=0
                          0, 0, 0, 0, //SET r0=0 (repeated instruction to account for vagaries in student implementation of the CPU class)
                         10, 0, 0, 0, //push r0
                         15, 0, 0, 0 }; //TRAP

        int allocSize = toPageSizeMultiple(progArr.length);
        int baseAddr = allocBlock(allocSize);
        //exit if not enough RAM for an idle process
        if(baseAddr == -1)
        {
        	printPageTable();
        	System.exit(0);
        }

        //Load the program into RAM
        for(int i = 0; i < progArr.length; i++)
        {
            m_MMU.write(baseAddr + i, progArr[i]);
        }

        //Save the register info from the current process (if there is one)
        if (m_currProcess != null)
        {
            m_currProcess.save(m_CPU);
        }
        
        //Set the appropriate registers
        m_CPU.setPC(baseAddr);
        m_CPU.setSP(baseAddr + progArr.length + 10);
        m_CPU.setBASE(baseAddr);
        m_CPU.setLIM(baseAddr + progArr.length + 20);

        //Save the relevant info as a new entry in m_processes
        m_currProcess = new ProcessControlBlock(IDLE_PROC_ID);
        m_currProcess.save(m_CPU);
        m_processes.add(m_currProcess);

    }//createIdleProcess


    /**
* printProcessTable **DEBUGGING**
*
* prints all the processes in the process table
*/
    private void printProcessTable()
    {
        debugPrintln("");
        debugPrintln("Process Table (" + m_processes.size() + " processes)");
        debugPrintln("======================================================================");
        for(ProcessControlBlock pi : m_processes)
        {
            debugPrintln(" " + pi);
        }//for
        debugPrintln("----------------------------------------------------------------------");

    }//printProcessTable

    /**
* removeCurrentProcess
*
* removes the process that is currently running from the process table. Adds address space
* to the list of free blocks in RAM
*
*/
    public void removeCurrentProcess()
    {
    	freeCurrProcessMemBlock();
        m_processes.remove(m_currProcess);
    }//removeCurrentProcess
    
/**
* getNewProcess
*
* selects a new process based on current running time and the highest average starve
* among unblocked processes
*
* @return new ProcessControlBlock or null if all processes are blocked
*/
    ProcessControlBlock getNewProcess()
    {
    	ProcessControlBlock newProc = null;
    	
    	//set to negative to ensure a process is chosen
    	double highestStarve = -1;
    	
    	if(m_processes.contains(m_currProcess) && !m_currProcess.isBlocked())
    	{
    		//add runtime if current process exists and isn't blocked
    		m_currProcess.addRunTime(m_CPU.getTicks() - lastInterrupt);
    		
    		//return current if it hasn't been running minimum time
    		if (m_currProcess.getRunTime() < MIN_RUN_TIME)
    		{
    			//update last interrupt before you return
    			lastInterrupt = m_CPU.getTicks();
    			
    			return m_currProcess;
    		}
    		
    		newProc = m_currProcess;
    		
    		//compare other processes to this starve time
    		highestStarve = newProc.avgStarve + 150;
    	}
    	
    	//find process with the highest average starve
        for(ProcessControlBlock proc : m_processes)
        {
        	if(!proc.isBlocked() && proc.avgStarve > highestStarve)
        	{
        		highestStarve = proc.avgStarve;
        		newProc = proc;
        		
        	}
        }
    	
    	//reset currProcess runtime if a different process is scheduled
    	if (newProc != m_currProcess && m_processes.contains(m_currProcess))
    	{
    		m_currProcess.resetRunTime();
    	}
    	
    	//update last interrupt
    	lastInterrupt = m_CPU.getTicks();
    	
    	return newProc;
    }//getNewProcess

    /**
* getRandomProcess
*
* selects a non-Blocked process at random from the ProcessTable.
*
* @return a reference to the ProcessControlBlock struct of the selected process
* -OR- null if no non-blocked process exists
*/
ProcessControlBlock getRandomProcess()
{
	//Calculate a random offset into the m_processes list
    int offset = ((int)(Math.random() * 2147483647)) % m_processes.size();
            
    //Iterate until a non-blocked process is found
    ProcessControlBlock newProc = null;
    for(int i = 0; i < m_processes.size(); i++)
    {
        newProc = m_processes.get((i + offset) % m_processes.size());
        if ( ! newProc.isBlocked())
        {
            return newProc;
        }
    }//for

    return null; // no processes are Ready
}//getRandomProcess
    
    /**
* scheduleNewProcess
*
* Selects a new process to run and saves the old process registers
* before loading the new ones.
*
* If there are no more processes available to run, end simulation.
*/
public void scheduleNewProcess()
{
	// Check to see if there are no more processes
	
    if(m_processes.size() == 0)
    {
     	System.exit(0);
    }
    
    //ProcessControlBlock newProcess = getNewProcess();
    ProcessControlBlock newProcess = getRandomProcess();
        
    if(newProcess == null)
    {
    	createIdleProcess();
    	return;
    }
    
    if(newProcess.getProcessId() == IDLE_PROC_ID)
    {
    	System.exit(0);
    }
    
    //If the current process is not the new process, save all the data, and restore the new one
    if(newProcess != m_currProcess){
    //save current process's registers
	    m_currProcess.save(m_CPU);
	    //Set the new process and restore its registers
	    m_currProcess = newProcess;
	    m_currProcess.restore(m_CPU);
    }
    
}//scheduleNewProcess

    
/**
* createProcess
*
* Exports program and loads RAM with program.
*
* @param prog
* Program object which contains the program to be loaded
* @param allocSize
* Size the RAM that is being allocated
*/
public void createProcess(Program prog, int allocSize)
{
	// Save the exported program into array
	int[] program = prog.export();
	
	if (m_currProcess != null)
	{
		m_currProcess.save(m_CPU);
	}
	
	allocSize = toPageSizeMultiple(allocSize);
	int nextAddr = allocBlock(allocSize);
	//don't create process if not enough space
	if (nextAddr == -1)
	{
		printPageTable();
		return;
	}
	
	// Set base and limit registers for CPU
	m_CPU.setBASE(nextAddr);
	
	m_CPU.setLIM(allocSize);
	
	m_CPU.setPC(nextAddr);
	
	m_CPU.setSP(nextAddr + allocSize);
	
	// Load program into memory
	for (int i = 0; i < prog.getSize(); i++)
		m_MMU.write(i + m_CPU.getBASE(), program[i]);
	
	ProcessControlBlock newProc = new ProcessControlBlock(m_nextProcessID);
	
	++m_nextProcessID;
	
	m_processes.add(newProc);
	
	//Add new process to process vector and make current process
	m_currProcess = newProc;
	
	//save current process
	m_currProcess.save(m_CPU);
	//print memory message
	printMemAlloc();
	
}// createProcess

/**
* pushToBlockedProc
*
* Pushes data to a location on a non-running process
* Optimization
*
* @param addr the address to write data to
* @param data the data to write
*/
public void pushToBlockedProc(int addr, int data)
{
	m_MMU.write(addr, data);
}


/*
* ======================================================================
* Program Management Methods
* ----------------------------------------------------------------------
*/


    /**
* addProgram
*
* registers a new program with the simulated OS that can be used when the
* current process makes an Exec system call. (Normally the program is
* specified by the process via a filename but this is a simulation so the
* calling process doesn't actually care what program gets loaded.)
*
* @param prog the program to add
*
*/
public void addProgram(Program prog)
{
    m_programs.add(prog);
}//addProgram

/*
* ======================================================================
* Interrupt Handlers
* ----------------------------------------------------------------------
*/

/**
* interruptIllegalMemoryAccess
*
* If an illegal memory address has been accessed, this method prints an error and quits the program
*
* @param addr
* The address that was illegally accessed
*/
public void interruptIllegalMemoryAccess(int addr)
{
	System.out.println("ERROR: Illegal Memory Access Address: " + addr);
	syscallExit();
}//interruptIllegalMemoryAccess

/**
* interruptDivideByZero
*
* If a divide by zero has been attempted this method issues an error message and quits the program
*
*/
public void interruptDivideByZero()
{
	System.out.println("ERROR: Divide By Zero");
	syscallExit();
}//interruptDivideByZero

/**
* interruptIllegalInstruction
*
* If an illegal instruction is attempted this method issues an error message and quits the program
*
* @param instr
* Array of ints which were illegal instructions
*/
public void interruptIllegalInstruction(int[] instr)
{
	System.out.println("ERROR: Illegal Instruction");
	m_CPU.printInstr(instr);
	syscallExit();
}//interruptIllegalInstruction

/**
* interruptIOReadComplete
*
* This method handles interrupts due to reads completing
*
* @param devID
* The id of the device
* @param addr
* The address the interrupt is coming from
* @param data
* The data that is being read from the device
*/
@Override
public void interruptIOReadComplete(int devID, int addr, int data) {
	//Find device
	DeviceInfo wantedDevice = getDeviceInfo(devID);

	//Make sure the wanted device exists
	if(wantedDevice.device != null)
	{
		// Find the waiting process and unblock it
		ProcessControlBlock blocked = selectBlockedProcess(wantedDevice.device, SYSCALL_READ, addr);
		blocked.unblock();
	
		//Find the position of the blocked's stack
		int otherSP = blocked.getRegisterValue(CPU.SP);
	
		//Write a success code to the correct position in the waiting proc's stack
		blocked.setRegisterValue(CPU.SP, otherSP + 1);
		otherSP++;
		pushToBlockedProc(otherSP, data);
		blocked.setRegisterValue(CPU.SP, otherSP + 1);
		otherSP++;
		pushToBlockedProc(otherSP, SYSTEM_HANDLER_SUCCESS);
	
	}
	else
	{
		m_CPU.push(DEVICE_NOT_FOUND_ERROR);
	}
}//InterrruptIOReadComplete

	/**
	* interruptIOWriteComplete
	*
	* This method handles interrupts due to writes completing on devices
	*
	* @param devID
	* The id of the device
	* @param addr
	* The address that the interrupt came from
	*/
	@Override
	public void interruptIOWriteComplete(int devID, int addr) {
	//Find device
	DeviceInfo wantedDevice = getDeviceInfo(devID);

	//PLEEZE BE NOT EMPTY
	if(wantedDevice.device != null)
	{
		//Find waiting process and unblock
		ProcessControlBlock blocked = selectBlockedProcess(wantedDevice.device, SYSCALL_WRITE, addr);
		blocked.unblock();
	
		//Find the position of the blocked's stack
		int otherSP = blocked.getRegisterValue(CPU.SP);
	
		//Write a success code to the correct position in the waiting proc's stack
		blocked.setRegisterValue(CPU.SP, otherSP + 1);
		otherSP++;
		pushToBlockedProc(otherSP, SYSTEM_HANDLER_SUCCESS);
	
	
	}
	else
		m_CPU.push(DEVICE_NOT_FOUND_ERROR);
}//interruptIOWriteComplete

/**
* interruptClock
*
* Schedules a new process
*/
public void interruptClock()
{
	scheduleNewProcess();
}


/*
* ======================================================================
* System Calls
* ----------------------------------------------------------------------
*/

/**
* systemCall
*
* The system call handler
*/
@Override
public void systemCall()
{
	switch (m_CPU.pop())
	{
		case SYSCALL_EXIT:
			syscallExit();
			break;
		case SYSCALL_OUTPUT:
			syscallOutput();
			break;
		case SYSCALL_GETPID:
			syscallGetPID();
			break;
		case SYSCALL_OPEN:
			syscallOpen();
			break;
		case SYSCALL_CLOSE:
			syscallClose();
			break;
		case SYSCALL_READ:
			syscallRead();
			break;
		case SYSCALL_WRITE:
			syscallWrite();
			break;
		case SYSCALL_EXEC:
			syscallExec();
			break;
		case SYSCALL_YIELD:
			syscallYield();
			break;
		case SYSCALL_COREDUMP:
			syscallCoreDump();
			break;
	}
}//systemCall

/**
* SYSCALL_EXIT
*
* Exits the system
*/
private void syscallExit()
{
	removeCurrentProcess();
	scheduleNewProcess();
}

/**
* SYSCALL_OUTPUT
*
* Outputs information on the stack to a device
*/
private void syscallOutput()
{
	System.out.println("\nOUTPUT: " + m_CPU.pop());
}

/**
* syscallGetPID
*
* Pushes the process ID of the current process to the stack
*/
private void syscallGetPID()
{
	m_CPU.push(m_currProcess.getProcessId());
}

/**
* syscallOpen
*
* Opens a device so that it can be used by the currently running process
*/
private void syscallOpen()
{
	int deviceID = m_CPU.pop();
	
	// Check to see that device exists
	DeviceInfo deviceIn = getDeviceInfo(deviceID);
	if(deviceIn != null)
	{
		//Check to see if its already open
		if(!deviceIn.containsProcess(m_currProcess))
		{
			//Check to make sure device shareable or unused
			if(deviceIn.unused() || (deviceIn.procs.size() > 0 && deviceIn.device.isSharable()))
			{
				deviceIn.procs.add(m_currProcess);
				m_CPU.push(SYSTEM_HANDLER_SUCCESS);
			}
			else
			{
				deviceIn.addProcess(m_currProcess);
				m_currProcess.block(m_CPU, deviceIn.getDevice(), SYSCALL_OPEN, 0);
				m_CPU.push(SYSTEM_HANDLER_SUCCESS);
				scheduleNewProcess();
			}
		}
		else
		{
			m_CPU.push(DEVICE_ALREADY_OPEN_ERROR);
		}
	}
	else
	{
		m_CPU.push(DEVICE_NOT_FOUND_ERROR);
	}
}//syscallOpen

/**
* syscallClose
*
* Closes a device so that it can no longer be used by the current process
*/
private void syscallClose()
{
	int deviceID = m_CPU.pop();

	// Check for device existence
	DeviceInfo deviceIn = getDeviceInfo(deviceID);
	if(deviceIn != null)
	{
		//Check if device open
		if(deviceIn.containsProcess(m_currProcess))
		{
			deviceIn.removeProcess(m_currProcess);

			//Find out if there is another process waiting for this device and unblock it if yes
			ProcessControlBlock blocked = selectBlockedProcess(deviceIn.getDevice(), SYSCALL_OPEN, 0);
			if(blocked != null)
			{
				blocked.unblock();
			}

			m_CPU.push(SYSTEM_HANDLER_SUCCESS);
		}
		else
		{
			m_CPU.push(DEVICE_NOT_OPEN_ERROR);
		}
	}
	else
	{
		m_CPU.push(DEVICE_NOT_FOUND_ERROR);
	}
}//syscallClose

/**
* syscallRead
*
* Reads information from a device by popping data off of the stack
*/
private void syscallRead()
{
	// get necessary information from the stack
	int address = m_CPU.pop();
	int deviceID = m_CPU.pop();
	
	//Check for device existence
	DeviceInfo deviceIn = getDeviceInfo(deviceID);
	if(deviceIn != null)
	{
		//Check to see if device is open
		if(deviceIn.containsProcess(m_currProcess))
		{
			//Check if device readable
			if(deviceIn.device.isReadable())
			{
				if(deviceIn.device.isAvailable())
				{
					deviceIn.device.read(address);
	
					//Now block and wait for it to come back
					m_currProcess.block(m_CPU, deviceIn.getDevice(), SYSCALL_READ, address);
				}
				else
				{
					m_CPU.push(deviceID);
					m_CPU.push(address);
					m_CPU.push(SYSCALL_READ);
					m_CPU.setPC(m_CPU.getPC() - CPU.INSTRSIZE);
				}
				scheduleNewProcess();
			}
			else
			{
				m_CPU.push(DEVICE_WRITE_ONLY_ERROR);
			}
		}
		else
		{
			m_CPU.push(DEVICE_NOT_OPEN_ERROR);
		}
	}
	else
	{
		m_CPU.push(DEVICE_NOT_FOUND_ERROR);
	}
}//syscallRead

/**
* syscallWrite
*
* Writes data to a device by pushing it onto the stack
*/
private void syscallWrite()
{	
	//Get necessary information from the stack
	int data = m_CPU.pop();
	int address = m_CPU.pop();
	int deviceID = m_CPU.pop();
	
	//Check for device existence
	DeviceInfo deviceIn = getDeviceInfo(deviceID);
	if(deviceIn != null)
		{
		//Check if device open
		if(deviceIn.containsProcess(m_currProcess))
		{
			//Check if device writeable
			if(deviceIn.device.isWriteable())
			{
				if(deviceIn.device.isAvailable())
				{
					//Write data to device
					deviceIn.device.write(address, data);
	
					//Block the process and wait for write to finish
					m_currProcess.block(m_CPU, deviceIn.device, SYSCALL_WRITE, address);
				}
				else
				{
					//Set PC to rexecute trap instruction and push all data back to stack
					m_CPU.push(deviceID);
					m_CPU.push(address);
					m_CPU.push(data);
					m_CPU.push(SYSCALL_WRITE);
					m_CPU.setPC(m_CPU.getPC() - CPU.INSTRSIZE);
				}
				scheduleNewProcess();
			}
			else
			{
				m_CPU.push(DEVICE_READ_ONLY_ERROR);
			}
		}
		else
		{
			m_CPU.push(DEVICE_NOT_OPEN_ERROR);
		}
	}
	else
	{
		m_CPU.push(DEVICE_NOT_FOUND_ERROR);
	}
}//syscallWrite

/**
* syscallExec
*
* creates a new process. The program used to create that process is chosen
* semi-randomly from all the programs that have been registered with the OS
* via {@link #addProgram}. Limits are put into place to ensure that each
* process is run an equal number of times. If no programs have been
* registered then the simulation is aborted with a fatal error.
*
*/
private void syscallExec()
{
    //If there is nothing to run, abort. This should never happen.
    if (m_programs.size() == 0)
    {
        System.err.println("ERROR! syscallExec has no programs to run.");
        System.exit(-1);
    }
        
    //find out which program has been called the least and record how many
    //times it has been called
    int leastCallCount = m_programs.get(0).callCount;
    for(Program prog : m_programs)
    {
        if (prog.callCount < leastCallCount)
        {
            leastCallCount = prog.callCount;
        }
    }
    //Create a vector of all programs that have been called the least number
    //of times
    Vector<Program> cands = new Vector<Program>();
    for(Program prog : m_programs)
    {
        cands.add(prog);
    }
        
    //Select a random program from the candidates list
    Random rand = new Random();
    int pn = rand.nextInt(m_programs.size());
    Program prog = cands.get(pn);
    //Determine the address space size using the default if available.
    //Otherwise, use a multiple of the program size.
    int allocSize = prog.getDefaultAllocSize();
    if (allocSize <= 0)
    {
        allocSize = prog.getSize() * 2;
    }
    
    int prevNumProc = m_processes.size();
    //Load the program into RAM
    createProcess(prog, allocSize);
    
    //don't decrement PC if a new process hasn't been created
    if (m_processes.size() == prevNumProc)
    {
    	return;
    }
	
    //Adjust the PC since it's about to be incremented by the CPU
    m_CPU.setPC(m_CPU.getPC() - CPU.INSTRSIZE);
 }//syscallExec


    
 /**
* Process can move from Running to Ready state
*/
 private void syscallYield()
 {
	 scheduleNewProcess();
 }//syscallYield

/**
* calls regDump from the CPU
*/
private void syscallCoreDump()
{
	m_CPU.regDump();
	System.out.println("OUTPUT: " + m_CPU.pop());
	System.out.println("OUTPUT: " + m_CPU.pop());
	System.out.println("OUTPUT: " + m_CPU.pop());
	syscallExit();
}


//======================================================================
	// Inner Classes
	//----------------------------------------------------------------------

	/**
	 * class ProcessControlBlock
	 *
	 * This class contains information about a currently active process.
	 */
	private class ProcessControlBlock implements Comparable<ProcessControlBlock>
	{
		/**
       * These are the process' current registers.  If the process is in the
       * "running" state then these are out of date
       */
      private int[] registers = null;

      /**
       * If this process is blocked a reference to the Device is stored here
       */
      private Device blockedForDevice = null;
      
      /**
       * If this process is blocked a reference to the type of I/O operation
       * is stored here (use the SYSCALL constants defined in SOS)
       */
      private int blockedForOperation = -1;
      
      /**
       * If this process is blocked reading from a device, the requested
       * address is stored here.
       */
      private int blockedForAddr = -1;
		
		/**
		 * a unique id for this process
		 */
		private int processId = 0;
		
		 /**
       * the time it takes to load and save registers, specified as a number
       * of CPU ticks
       */
      private static final int SAVE_LOAD_TIME = 30;
      
      /**
       * Used to store the system time when a process is moved to the Ready
       * state.
       */
      private int lastReadyTime = -1;
      
      /**
       * Used to store the number of times this process has been in the ready
       * state
       */
      private int numReady = 0;
      
      /**
       * Used to store the maximum starve time experienced by this process
       */
      private int maxStarve = -1;
      
      /**
       * Used to store the average starve time for this process
       */
      private double avgStarve = 0;
      
      private double runTime = 0;
      

		/**
		 * constructor
		 *
		 * @param pid        a process id for the process.  The caller is
		 *                   responsible for making sure it is unique.
		 */
		public ProcessControlBlock(int pid)
		{
			this.processId = pid;
		}

		/**
		 * @return the current process' id
		 */
		public int getProcessId()
		{
			return this.processId;
		}
		
		/**
       * getRegisterValue
       *
       * Retrieves the value of a process' register that is stored in this
       * object (this.registers).
       * 
       * @param idx the index of the register to retrieve.  Use the constants
       *            in the CPU class
       * @return one of the register values stored in in this object or -999
       *         if an invalid index is given 
       */
      public int getRegisterValue(int idx)
      {
          if ((idx < 0) || (idx >= CPU.NUMREG))
          {
              return -999;    // invalid index
          }
          
          return this.registers[idx];
      }//getRegisterValue
      
      /**
       * @return the last time this process was put in the Ready state
       */
      public long getLastReadyTime()
      {
          return lastReadyTime;
      }
       
      /**
       * setRegisterValue
       *
       * Sets the value of a process' register that is stored in this
       * object (this.registers).  
       * 
       * @param idx the index of the register to set.  Use the constants
       *            in the CPU class.  If an invalid index is given, this
       *            method does nothing.
       * @param val the value to set the register to
       */
      public void setRegisterValue(int idx, int val)
      {
          if ((idx < 0) || (idx >= CPU.NUMREG))
          {
              return;    // invalid index
          }
          
          this.registers[idx] = val;
      }//setRegisterValue
		
      public double getRunTime()
      {
      	return runTime;
      }
      
      public void addRunTime(double newTime)
      {
      	runTime = runTime + newTime;
      }
      
      public void resetRunTime()
      {
      	runTime = 0;
      }
      
      /**
       * save
       *
       * saves the current CPU registers into this.registers
       *
       * @param cpu  the CPU object to save the values from
       */
      public void save(CPU cpu)
      {
          //A context switch is expensive.  We simluate that here by 
          //adding ticks to m_CPU
          m_CPU.addTicks(SAVE_LOAD_TIME);
          
          //Save the registers
          int[] regs = cpu.getRegisters();
          this.registers = new int[CPU.NUMREG];
          for(int i = 0; i < CPU.NUMREG; i++)
          {
              this.registers[i] = regs[i];
          }

          //Assuming this method is being called because the process is moving
          //out of the Running state, record the current system time for
          //calculating starve times for this process.  If this method is
          //being called for a Block, we'll adjust lastReadyTime in the
          //unblock method.
          numReady++;
          lastReadyTime = m_CPU.getTicks();
          
      }//save
       
      /**
       * restore
       *
       * restores the saved values in this.registers to the current CPU's
       * registers
       *
       * @param cpu  the CPU object to restore the values to
       */
      public void restore(CPU cpu)
      {
          //A context switch is expensive.  We simluate that here by 
          //adding ticks to m_CPU
          m_CPU.addTicks(SAVE_LOAD_TIME);
          
          //Restore the register values
          int[] regs = cpu.getRegisters();
          for(int i = 0; i < CPU.NUMREG; i++)
          {
              regs[i] = this.registers[i];
          }

          //Record the starve time statistics
          int starveTime = m_CPU.getTicks() - lastReadyTime;
          if (starveTime > maxStarve)
          {
              maxStarve = starveTime;
          }
          double d_numReady = (double)numReady;
          avgStarve = avgStarve * (d_numReady - 1.0) / d_numReady;
          avgStarve = avgStarve + (starveTime * (1.0 / d_numReady));
      }//restore
      
      /**
       * block
       *
       * blocks the current process to wait for I/O.  The caller is
       * responsible for calling {@link CPU#scheduleNewProcess}
       * after calling this method.
       *
       * @param cpu   the CPU that the process is running on
       * @param dev   the Device that the process must wait for
       * @param op    the operation that the process is performing on the
       *              device.  Use the SYSCALL constants for this value.
       * @param addr  the address the process is reading from (for SYSCALL_READ)
       * 
       */
      public void block(CPU cpu, Device dev, int op, int addr)
      {
          blockedForDevice = dev;
          blockedForOperation = op;
          blockedForAddr = addr;
          
      }//block
      
      /**
       * unblock
       *
       * moves this process from the Blocked (waiting) state to the Ready
       * state. 
       *
       */
      public void unblock()
      {
          //Reset the info about the block
          blockedForDevice = null;
          blockedForOperation = -1;
          blockedForAddr = -1;
          
          //Assuming this method is being called because the process is moving
          //from the Blocked state to the Ready state, record the current
          //system time for calculating starve times for this process.
          lastReadyTime = m_CPU.getTicks();
          
      }//unblock
      
      /**
       * isBlocked
       *
       * @return true if the process is blocked
       */
      public boolean isBlocked()
      {
          return (blockedForDevice != null);
      }//isBlocked
       
      /**
       * isBlockedForDevice
       *
       * Checks to see if the process is blocked for the given device,
       * operation and address.  If the operation is not an open, the given
       * address is ignored.
       *
       * @param dev   check to see if the process is waiting for this device
       * @param op    check to see if the process is waiting for this operation
       * @param addr  check to see if the process is reading from this address
       *
       * @return true if the process is blocked by the given parameters
       */
      public boolean isBlockedForDevice(Device dev, int op, int addr)
      {
          if ( (blockedForDevice == dev) && (blockedForOperation == op) )
          {
              if (op == SYSCALL_OPEN)
              {
                  return true;
              }

              if (addr == blockedForAddr)
              {
                  return true;
              }
          }//if

          return false;
      }//isBlockedForDevice
      
      /**
       * overallAvgStarve
       *
       * @return the overall average starve time for all currently running
       *         processes
       *
       */
      public double overallAvgStarve()
      {
          double result = 0.0;
          int count = 0;
          for(ProcessControlBlock pi : m_processes)
          {
              if (pi.avgStarve > 0)
              {
                  result = result + pi.avgStarve;
                  count++;
              }
          }
          if (count > 0)
          {
              result = result / count;
          }
          
          return result;
      }//overallAvgStarve
       
      /**
       * toString       **DEBUGGING**
       *
       * @return a string representation of this class
       */
      public String toString()
      {
          //Print the Process ID and process state (READY, RUNNING, BLOCKED)
          String result = "Process id " + processId + " ";
          if (isBlocked())
          {
              result = result + "is BLOCKED for ";
              //Print device, syscall and address that caused the BLOCKED state
              if (blockedForOperation == SYSCALL_OPEN)
              {
                  result = result + "OPEN";
              }
              else
              {
                  result = result + "WRITE @" + blockedForAddr;
              }
              for(DeviceInfo di : m_devices)
              {
                  if (di.getDevice() == blockedForDevice)
                  {
                      result = result + " on device #" + di.getId();
                      break;
                  }
              }
              result = result + ": ";
          }
          else if (this == m_currProcess)
          {
              result = result + "is RUNNING: ";
          }
          else
          {
              result = result + "is READY: ";
          }

          //Print the register values stored in this object.  These don't
          //necessarily match what's on the CPU for a Running process.
          if (registers == null)
          {
              result = result + "<never saved>";
              return result;
          }
          
          for(int i = 0; i < CPU.NUMGENREG; i++)
          {
              result = result + ("r" + i + "=" + registers[i] + " ");
          }//for
          result = result + ("PC=" + registers[CPU.PC] + " ");
          result = result + ("SP=" + registers[CPU.SP] + " ");
          result = result + ("BASE=" + registers[CPU.BASE] + " ");
          result = result + ("LIM=" + registers[CPU.LIM] + " ");

          //Print the starve time statistics for this process
          result = result + "\n\t\t\t";
          result = result + " Max Starve Time: " + maxStarve;
          result = result + " Avg Starve Time: " + avgStarve;
      
          return result;
      }//toString
       
      /**
       * compareTo              
       *
       * compares this to another ProcessControlBlock object based on the BASE addr
       * register.  Read about Java's Collections class for info on
       * how this method can be quite useful to you.
       */
      public int compareTo(ProcessControlBlock pi)
      {
          return this.registers[CPU.BASE] - pi.registers[CPU.BASE];
      }
      
      /**
       * move
       * 
       * moves a page to a new frame based on the value of the
       * new base given. 
       * 
       * @param newBase
       * @return true if move successful, false otherwise
       */
      public boolean move(int newBase)
      {  
    	  //check if process will fit in RAM
    	  if (newBase + registers[CPU.LIM] > m_MMU.getSize())
    	  {
    		  return false;
    	  }
    	  
    	  //save if process is currently running
    	  if (this == m_currProcess)
    	  {
    		  save(m_CPU);
    	  }
    	   	  
    	  //old register values
    	  int oldBase = registers[CPU.BASE];
    	  int oldPC = registers[CPU.PC];
    	  int oldSP = registers[CPU.SP];
    	  
    	  //difference between old and new base
    	  int baseDiff = newBase - oldBase;
    	  
    	  //current page the process starts on
    	  int startPage = oldBase / m_MMU.getPageSize();
          //get page number the process is moving to
  	  	  int newPage = newBase / m_MMU.getPageSize();
        
          //number of pages process takes up
          int numPages = registers[CPU.LIM] / m_MMU.getPageSize();
          
          int oldEntry;
          int newEntry;
          for (int i = 0; i < numPages; ++i)
          {
        	  oldEntry = m_MMU.read(startPage + i);
        	  newEntry = m_MMU.read(newPage + i);
        	  
        	  //swap the contents of old page and new page
        	  m_MMU.write(startPage + i, newEntry);
        	  m_MMU.write(newPage + i, oldEntry);
        	  
          }
    	  
          //debug message
          if (startPage != newPage)
          {
        	  debugPrintln("Process " + getProcessId() + " moved from frame " + 
        			  	   startPage + " to " + newPage);
          }
    	  
    	  //update base, PC, and SP of process
    	  this.setRegisterValue(CPU.BASE, newBase);
    	  this.setRegisterValue(CPU.PC,oldPC + baseDiff);
    	  this.setRegisterValue(CPU.SP, oldSP + baseDiff);
    	  
    	  //update CPU if this is current process
    	  if (this == m_currProcess)
    	  {
    		  restore(m_CPU);
    	  }
    	  
    	  
          return true;
      }//move

  }//class ProcessControlBlock

	/**
	 * class DeviceInfo`
	 *
	 * This class contains information about a device that is currently
	 * registered with the system.
	 */
	private class DeviceInfo
	{
		/** every device has a unique id */
		private int id;
		/** a reference to the device driver for this device */
		private Device device;
		/** a list of processes that have opened this device */
		private Vector<ProcessControlBlock> procs;

		/**
		 * constructor
		 *
		 * @param d          a reference to the device driver for this device
		 * @param initID     the id for this device.  The caller is responsible
		 *                   for guaranteeing that this is a unique id.
		 */
		public DeviceInfo(Device d, int initID)
		{
			this.id = initID;
			this.device = d;
			d.setId(initID);
			this.procs = new Vector<ProcessControlBlock>();
		}

		/** @return the device's id */
		public int getId()
		{
			return this.id;
		}

		/** @return this device's driver */
		public Device getDevice()
		{
			return this.device;
		}

		/** Register a new process as having opened this device */
		public void addProcess(ProcessControlBlock pi)
		{
			procs.add(pi);
		}

		/** Register a process as having closed this device */
		public void removeProcess(ProcessControlBlock pi)
		{
			procs.remove(pi);
		}

		/** Does the given process currently have this device opened? */
		public boolean containsProcess(ProcessControlBlock pi)
		{
			return procs.contains(pi);
		}

		/** Is this device currently not opened by any process? */
		public boolean unused()
		{
			return procs.size() == 0;
		}

	}//class DeviceInfo
	
	/*======================================================================
	 * Device Management Methods
	 *----------------------------------------------------------------------
	 */

	/**
	 * registerDevice
	 *
	 * adds a new device to the list of devices managed by the OS
	 *
	 * @param dev     the device driver
	 * @param id      the id to assign to this device
	 * 
	 */
	public void registerDevice(Device dev, int id)
	{
		m_devices.add(new DeviceInfo(dev, id));
	}//registerDevice
	
	/**
     * class MemBlock
     *
     * This class contains relevant info about a memory block in RAM.
     *
     */
    private class MemBlock implements Comparable<MemBlock>
    {
        /** the address of the block */
        private int m_addr;
        /** the size of the block */
        private int m_size;

        /**
         * ctor does nothing special
         */
        public MemBlock(int addr, int size)
        {
            m_addr = addr;
            m_size = size;
        }

        /** accessor methods */
        public int getAddr() { return m_addr; }
        public int getSize() { return m_size; }
        
        
        /**
         * compareTo              
         *
         * compares this to another MemBlock object based on address
         */
        public int compareTo(MemBlock m)
        {
            return this.m_addr - m.m_addr;
        }

    }//class MemBlock
    
    /*======================================================================
     * Memory Block Management Methods
     *----------------------------------------------------------------------
     */
 

    /**
     * allockBlock
     * 
     * decides where to load a new process given the size of its address space
     * @param size: size needed for the process
     * 
     * @return the address of the block that's been allocated
     */
    private int allocBlock(int size)
    {
      
      int freeSpace = getFreeSpace();
      
      //check if there's enough size in RAM
      if (freeSpace < size)
      {
          return -1;
      }
      
      
      MemBlock currBlock,remainder;
  	  int bBase;
  	  int bSize;
  	  //check if there's one sufficiently large block
  	  for (int i = 0; i < m_freeList.size(); ++i)
  	  {
  		  //current block's base and limit
  		  currBlock = m_freeList.get(i);
  		  bBase = currBlock.getAddr();
  		  bSize = currBlock.getSize();
  		  
  		  //check if process can fit in block
  		  if (bSize >= size)
  		  {
  			  remainder = new MemBlock(bBase+size, bSize-size);
  			  //remove the current block
  			  m_freeList.remove(currBlock);
  			  //add remaining space of block
  			  if (remainder.getSize() > 0)
  			  {
  				  m_freeList.add(remainder);
  			  }
  			  return bBase;
  		  }
  	  }
  	  
  	  
  	  //move all processes to the front so that there is one block of memory
  	  //at the end of RAM
      System.out.println("Moving processes...");
      Collections.sort(m_processes);
      int procSize = m_processes.size();
      ProcessControlBlock currProc;
      int currSize;
      int nextStart = m_MMU.getNumPages();
      //move all processes to front
      for (int j = 0; j < procSize;++j)
      {
    	  currProc = m_processes.get(j);
    	  currSize = currProc.getRegisterValue(CPU.LIM); 
    	  //move process
    	  currProc.move(nextStart);
    	  //update next move address
    	  nextStart += currSize;	  
      }
      
      //remove all free blocks and add one to the end
      ProcessControlBlock lastProc = m_processes.lastElement();
      //free block starts at the limit of the last process
      int lastLim = lastProc.getRegisterValue(CPU.BASE) + lastProc.getRegisterValue(CPU.LIM);
      m_freeList.removeAllElements();
      m_freeList.add(new MemBlock(lastLim,freeSpace));
      
      //add remainder, if any
      remainder = new MemBlock(lastLim+size, freeSpace-size);
      m_freeList.removeAllElements();
      if(remainder.getSize() > 0)
      {
    	  m_freeList.add(remainder);
      }

      
      //return limit of last process
      return lastLim;
      
    }//allocBlock

    /**
     * freeCurrProcessMemBlock
     * adjusts m_freeList to account for the fact
     * that the current process is about to be killed. When doing this,
     * make sure that you merge together any adjacent free memory blocks that results.
     */
    private void freeCurrProcessMemBlock()
    {
        int currBase = m_currProcess.getRegisterValue(CPU.BASE);
        int currSize = m_currProcess.getRegisterValue(CPU.LIM);
        MemBlock newFree = new MemBlock(currBase,currSize);
        MemBlock leftAdj = null;
        m_freeList.add(newFree);
        
        Collections.sort(m_freeList);
        
        //get index of new block
        int freeIdx = m_freeList.indexOf(newFree);
        
        //check for left adjacency
        if (freeIdx > 0)
        {
        	if (isAdjacent(newFree,m_freeList.get(freeIdx-1)))
        	{
        		leftAdj = m_freeList.get(freeIdx-1);
        		merge(newFree,leftAdj);
        	}
        }
        
        //update newFree if it has been merged
        if (leftAdj != null)
        {
        	for(MemBlock fb:m_freeList)
        	{
        		if (fb.getAddr() == leftAdj.getAddr())
        		{
        			newFree = fb;
        			break;
        		}
        	}
        	Collections.sort(m_freeList);
            freeIdx = m_freeList.indexOf(newFree);
        }
        
        
        //check for right adjacency
        if (freeIdx < (m_freeList.size()-1))
        {
        	if (isAdjacent(newFree,m_freeList.get(freeIdx+1)))
        	{
        		merge(newFree,m_freeList.get(freeIdx+1));
        	}
        }
        
    }//freeCurrProcessMemBlock
    
    /*======================================================================
     * Virtual Memory Methods
     *----------------------------------------------------------------------
     */

    /**
     * initPageTable
     * 
     * initializes an area of RAM that MMU will use 
     * for its page table
     */
    private void initPageTable()
    {
    	int numPages = m_MMU.getNumPages();
    	int numFrames = m_MMU.getNumFrames();
    	
    	//write page table to bottom of RAM (Starting at 0)
    	for (int i = 0; i < numPages; ++i)
    	{
    		if (i < numFrames)
    		{
    			m_RAM.write(i,i);
    		}
    		
    		//write a -1 if a page is not loaded in RAM
    		else
    		{
    			m_RAM.write(i, -1);
    		}
    	}
    	
    }//initPageTable


    /**
     * createPageTableEntry
     *
     * is a helper method for {@link #printPageTable} to create a single entry
     * in the page table to print to the console.  This entry is formatted to be
     * exactly 35 characters wide by appending spaces.
     *
     * @param pageNum is the page to print an entry for
     *
     */
    private String createPageTableEntry(int pageNum)
    {
        int frameNum = m_MMU.read(pageNum);
        int baseAddr = frameNum * m_MMU.getPageSize();

        //check to see if student has pre-shifted frame numbers
        //in their page table and, if so, correct the values
        if (frameNum / m_MMU.getPageSize() != 0)
        {
            baseAddr = frameNum;
            frameNum /= m_MMU.getPageSize();
        }

        String entry = "page " + pageNum + "-->frame "
                          + frameNum + " (@" + baseAddr +")";

        //pad out to 35 characters
        String format = "%s%" + (35 - entry.length()) + "s";
        return String.format(format, entry, " ");
        
    }//createPageTableEntry

    /**
     * printPageTable      *DEBUGGING*
     *
     * prints the page table in a human readable format
     *
     */
    private void printPageTable()
    {
        //If verbose mode is off, do nothing
        if (!m_verbose) return;

        //Print a header
        System.out.println("\n----------========== Page Table ==========----------");

        //Print the entries in two columns
        for(int i = 0; i < m_MMU.getNumPages() / 2; i++)
        {
            String line = createPageTableEntry(i);                       //left column
            line += createPageTableEntry(i + (m_MMU.getNumPages() / 2)); //right column
            System.out.println(line);
        }
        
        //Print a footer
        System.out.println("-----------------------------------------------------------------");
        
    }//printPageTable
    
    
    /**
     * printMemAlloc                 *DEBUGGING*
     *
     * outputs the contents of m_freeList and m_processes to the console and
     * performs a fragmentation analysis.  It also prints the value in
     * RAM at the BASE and LIMIT registers.  This is useful for
     * tracking down errors related to moving process in RAM.
     *
     * SIDE EFFECT:  The contents of m_freeList and m_processes are sorted.
     *
     */
    private void printMemAlloc()
    {
        //If verbose mode is off, do nothing
        if (!m_verbose) return;

        //Print a header
        System.out.println("\n----------========== Memory Allocation Table ==========----------");
        
        //Sort the lists by address
        Collections.sort(m_processes);
        Collections.sort(m_freeList);

        //Initialize references to the first entry in each list
        MemBlock m = null;
        ProcessControlBlock pi = null;
        ListIterator<MemBlock> iterFree = m_freeList.listIterator();
        ListIterator<ProcessControlBlock> iterProc = m_processes.listIterator();
        if (iterFree.hasNext()) m = iterFree.next();
        if (iterProc.hasNext()) pi = iterProc.next();

        //Loop over both lists in order of their address until we run out of
        //entries in both lists
        while ((pi != null) || (m != null))
        {
            //Figure out the address of pi and m.  If either is null, then assign
            //them an address equivalent to +infinity
            int pAddr = Integer.MAX_VALUE;
            int mAddr = Integer.MAX_VALUE;
            if (pi != null)  pAddr = pi.getRegisterValue(CPU.BASE);
            if (m != null)  mAddr = m.getAddr();

            //If the process has the lowest address then print it and get the
            //next process
            if ( mAddr > pAddr )
            {
                int size = pi.getRegisterValue(CPU.LIM);
                System.out.print(" Process " + pi.processId +  " (addr=" + pAddr + " size=" + size + " words");
                System.out.print(" / " + (size / m_MMU.getPageSize()) + " pages)" );
                System.out.print(" @BASE=" + m_MMU.read(pi.getRegisterValue(CPU.BASE))
                                 + " @SP=" + m_MMU.read(pi.getRegisterValue(CPU.SP)));
                System.out.println();
                if (iterProc.hasNext())
                {
                    pi = iterProc.next();
                }
                else
                {
                    pi = null;
                }
            }//if
            else
            {
                //The free memory block has the lowest address so print it and
                //get the next free memory block
                System.out.println("    Open(addr=" + mAddr + " size=" + m.getSize() + ")");
                if (iterFree.hasNext())
                {
                    m = iterFree.next();
                }
                else
                {
                    m = null;
                }
            }//else
        }//while
            
        //Print a footer
        System.out.println("-----------------------------------------------------------------");
        
    }//printMemAlloc
    
};// class SOS
