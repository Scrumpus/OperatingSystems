package sos;

import java.util.*;

/**
 * This class contains the simulated operating system (SOS).  Realistically it
 * would run on the same processor (CPU) that it is managing but instead it uses
 * the real-world processor in order to allow a focus on the essentials of
 * operating system design using a high level programming language.
 *
 * @authors Devon Griggs, Scott Schwalbe
 */
   
public class SOS implements CPU.TrapHandler
{
	
    //======================================================================
    //Constants
    //----------------------------------------------------------------------

    //These constants define the system calls this OS can currently handle
    public static final int SYSCALL_EXIT     = 0;    /* exit the current program */
    public static final int SYSCALL_OUTPUT   = 1;    /* outputs a number */
    public static final int SYSCALL_GETPID   = 2;    /* get current process id */
    public static final int SYSCALL_COREDUMP = 9;    /* print process state and exit */
    public static final int SYSCALL_OPEN    = 3;    /* access a device */
    public static final int SYSCALL_CLOSE   = 4;    /* release a device */
    public static final int SYSCALL_READ    = 5;    /* get input from device */
    public static final int SYSCALL_WRITE   = 6;    /* send output to device */
    public static final int SYSCALL_EXEC    = 7;    /* spawn a new process */
    public static final int SYSCALL_YIELD   = 8;    /* yield the CPU to another process */
    
    //Constants define success/error
    public static final int SUCCESS = 0;
    public static final int ERROR_UNKNOWN_DEVICE = -1;
    public static final int ERROR_DEVICE_NOT_SHARABLE = -2;
    public static final int ERROR_DEVICE_ALREADY_OPEN = -3;
    public static final int ERROR_DEVICE_NOT_OPEN = -4;
    public static final int ERROR_READ_ONLY = -5;
    public static final int ERROR_WRITE_ONLY = -6;

    		
	
    //======================================================================
    //Member variables
    //----------------------------------------------------------------------

    /**
     * This flag causes the SOS to print lots of potentially helpful
     * status messages
     **/
    public static final boolean m_verbose = false;
    
    /**
     * The CPU the operating system is managing.
     **/
    private CPU m_CPU = null;
    
    /**
     * The RAM attached to the CPU.
     **/
    private RAM m_RAM = null;
    
    /**
     * An arbitrary variable for the base value for memory.
     **/
    private int base = 21;
    
    /**
     * ProcessControlBlock of current process.
     */
    private ProcessControlBlock m_currProcess;
    
    /**
     * DeviceInfo objects currently installed in the system.
     */
    private Vector<DeviceInfo> m_devices = new Vector<DeviceInfo>(); 

    /*======================================================================
     * Constructors & Debugging
     *----------------------------------------------------------------------
     */
    
    /**
     * The constructor does nothing special
     */
    public SOS(CPU c, RAM r)
    {
        //Init member list
        m_CPU = c;
        m_RAM = r;
        m_currProcess = new ProcessControlBlock(42);
    	m_CPU.registerTrapHandler(this);
    }//SOS ctor
    
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
    
    /*======================================================================
     * Memory Block Management Methods
     *----------------------------------------------------------------------
     */

    //None yet!
    
    /*======================================================================
     * Device Management Methods
     *----------------------------------------------------------------------
     */

    //None yet!
    
    /*======================================================================
     * Process Management Methods
     *----------------------------------------------------------------------
     */

    /**
     * printProcessTable      **DEBUGGING**
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
            debugPrintln("    " + pi);
        }//for
        debugPrintln("----------------------------------------------------------------------");

    }//printProcessTable

    //<method header needed>
    public void removeCurrentProcess()
    {
        //%%%You will implement this method
    }//removeCurrentProcess

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

        return null;        // no processes are Ready
    }//getRandomProcess
    
    //<method header needed>
    public void scheduleNewProcess()
    {
        //%%%You will implement this method

    }//scheduleNewProcess

    /**
     * addProgram
     *
     * registers a new program with the simulated OS that can be used when the
     * current process makes an Exec system call.  (Normally the program is
     * specified by the process via a filename but this is a simulation so the
     * calling process doesn't actually care what program gets loaded.)
     *
     * @param prog  the program to add
     *
     */
    public void addProgram(Program prog)
    {
        m_programs.add(prog);
    }//addProgram
    
    /*======================================================================
     * Program Management Methods
     *----------------------------------------------------------------------
     */

    //insert method header here
    public void createProcess(Program prog, int allocSize)
    {
        
    	int testProcess[] = prog.export(); //load parsed process
        
    	if(prog.getSize() >= allocSize){
    		allocSize = prog.getSize()*3; //enlarge allocSize to fit program
    	}
        
        int stackSize = allocSize - prog.getSize();
        
        m_CPU.setBASE(base); //Set base to arbitrary value (can be changed above)
        
        m_CPU.setLIM(allocSize); 
        
        m_CPU.setPC(m_CPU.getBASE()); 
        
        m_CPU.setSP(m_CPU.getBASE() + allocSize - stackSize); 
        
        //load the program into memory so it can execute
        for(int i = 0; i < testProcess.length; i++){
        	m_RAM.write(i + m_CPU.getBASE(), testProcess[i]);
        }//for

    }//createProcess
        
    /*======================================================================
     * Interrupt Handlers
     *----------------------------------------------------------------------
     */

    //None yet!
    
    /*======================================================================
     * System Calls
     *----------------------------------------------------------------------
     */
    
    public void systemCall()
    {
    	
    	int syscall_input = m_CPU.pop();
    	
    	switch (syscall_input) {
		case SYSCALL_EXIT:
			handleSyscallExit();
			break;
		case SYSCALL_OUTPUT:
			handleSyscallOutput();
			break;
		case SYSCALL_GETPID:
			handleSyscallGetPID();
			break;
		case SYSCALL_COREDUMP:
			handleSyscallCoreDump();
			break;
		case SYSCALL_OPEN:
			handleSyscallOpen();
			break;
		case SYSCALL_CLOSE:
			handleSyscallClose();
			break;
		case SYSCALL_READ:
			handleSyscallRead();
			break;
		case SYSCALL_WRITE:
			handleSyscallWrite();
			break;
		case SYSCALL_EXEC:
			syscallExec();
		case SYSCALL_YIELD:
			syscallYield();
		default:
			break;
		}
    	
    }
    
    /**
     * handleSyscallExit
     * 
     * Terminates the program
     */
    public void handleSyscallExit() {
    	System.exit(0);
    }
    
    
    /**
     * handleSyscallOutput
     * 
     * Pops an item off the stack and prints it to console
     */
    public void handleSyscallOutput() {
    	int output = m_CPU.pop();
    	
    	System.out.println("OUTPUT: " + output);
    }

    
    /**
     * handleSyscallGetPID
     * 
     * Not yet implemented, pushes 42 to the stack
     */
    public void handleSyscallGetPID() {
    	m_CPU.push(42);
    }
    
    
    /**
     * handleSyscallCoreDump
     * 
     * calls CPU.regDump, prints the top 3 items on the stack, terminates the program
     * 
     */
    public void handleSyscallCoreDump() {
    	m_CPU.regDump();
    	
    	int output = m_CPU.pop();
    	System.out.println("OUTPUT: " + output);

    	output = m_CPU.pop();
    	System.out.println("OUTPUT: " + output);
    
    	output = m_CPU.pop();
    	System.out.println("OUTPUT: " + output);
    
    	System.exit(0);
    }
    
    /**
     * handleSyscallOpen
     * 
     * Performs an open operation. Indicates the process is currently using the device.
     * 
     */
    public void handleSyscallOpen() {
    	// Retrieve the device number from the stack.
    	int deviceNum = m_CPU.pop();
    	// Retrieve device info.
    	for(int i = 0; i < m_devices.size(); ++i)
    	{
    		if(m_devices.get(i).getId() == deviceNum)
    		{
    			// Check if device is not sharable.
    			if (!m_devices.get(i).getDevice().isSharable() && !m_devices.get(i).unused())
    			{
    				m_CPU.push(ERROR_DEVICE_NOT_SHARABLE);
    				return;
    			}
    			// Check if device is already open.
    			if(m_devices.get(i).containsProcess(m_currProcess))
    			{
    				m_CPU.push(ERROR_DEVICE_ALREADY_OPEN);
    				return;
    			}
    			// Add current process to vector.
    			m_devices.get(i).addProcess(m_currProcess);
    			m_CPU.push(SUCCESS);
    			return;
    		}
    	}
    	// Device is not found.
    	m_CPU.push(ERROR_UNKNOWN_DEVICE);
    	return;
    }
    
    /**
     * handleSyscallClose
     * 
     * Unassigns the device to the process.
     * 
     */
    public void handleSyscallClose() {
    	// Retrieve the device number from the stack.
    	int deviceNum = m_CPU.pop();
    	// Retrieve device info.
    	for(int i = 0; i < m_devices.size(); ++i)
    	{
    		if(m_devices.get(i).getId() == deviceNum)
    		{
    			// Check if device is not open.
    			if (!m_devices.get(i).containsProcess(m_currProcess))
    			{
    				m_CPU.push(ERROR_DEVICE_NOT_OPEN);
    				return;
    			}
    			// Remove process.
    			m_devices.get(i).removeProcess(m_currProcess);
    			m_CPU.push(SUCCESS);
    			return;
    		}
    	}
    	// Device not found.
    	m_CPU.push(ERROR_UNKNOWN_DEVICE);
    	return;
    }
    
    /**
     * handleSyscallRead
     * 
     * Calls the read method on the device.
     * 
     */
    public void handleSyscallRead() {
    	// Retrieve address and deviceNum from stack.
    	int address = m_CPU.pop();
    	int deviceNum = m_CPU.pop();   
    	// Retrieve device info.
    	for(int i = 0; i < m_devices.size(); ++i)
    	{
    		if(m_devices.get(i).getId() == deviceNum)
    		{
    			// CHeck if device not open.
    			if(!m_devices.get(i).containsProcess(m_currProcess))
    			{
    				m_CPU.push(ERROR_DEVICE_NOT_OPEN);
    				return;
    			}
    			// Check if device is write only.
    			if(!m_devices.get(i).getDevice().isReadable())
    			{
    				m_CPU.push(ERROR_WRITE_ONLY);
    				return;
    			}
    			int value = m_devices.get(i).getDevice().read(address);
    			m_CPU.push(value);
    			m_CPU.push(SUCCESS);
    			return;
    		}
    	}
    	// Device not found.
    	m_CPU.push(ERROR_UNKNOWN_DEVICE);
    	return;
    }
    
    /**
     * handleSyscallWrite
     * 
     * Calls the write method on the device.
     * 
     */
    public void handleSyscallWrite() {
    	// Retrieve device data, address, and deviceNum from stack.
    	int data = m_CPU.pop();
    	int address = m_CPU.pop();
    	int deviceNum = m_CPU.pop();
    	// Retrieve device info.
    	for(int i = 0; i < m_devices.size(); ++i)
    	{
    		if(m_devices.get(i).getId() == deviceNum)
    		{
    			// Check if device is not open.
    			if (!m_devices.get(i).containsProcess(m_currProcess))
    			{
    				m_CPU.push(ERROR_DEVICE_NOT_OPEN);
    				return;
    			}
    			// Check if device is read only.
    			if(!m_devices.get(i).getDevice().isWriteable())
    			{
    				m_CPU.push(ERROR_READ_ONLY);
    				return;
    			}
    			// Write to device.
    			m_devices.get(i).getDevice().write(address, data);
    			m_CPU.push(SUCCESS);
    			return;
    		}
    	}
    	// Device not found
    	m_CPU.push(ERROR_UNKNOWN_DEVICE);
    	return;
    }
    
    /**
     * syscallExec
     *
     * creates a new process.  The program used to create that process is chosen
     * semi-randomly from all the programs that have been registered with the OS
     * via {@link #addProgram}.  Limits are put into place to ensure that each
     * process is run an equal number of times.  If no programs have been
     * registered then the simulation is aborted with a fatal error.
     *
     */
    private void syscallExec()
    {
        //If there is nothing to run, abort.  This should never happen.
        if (m_programs.size() == 0)
        {
            System.err.println("ERROR!  syscallExec has no programs to run.");
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

        //Load the program into RAM
        createProcess(prog, allocSize);

        //Adjust the PC since it's about to be incremented by the CPU
        m_CPU.setPC(m_CPU.getPC() - CPU.INSTRSIZE);

    }//syscallExec


    
    //<method header needed>
    private void syscallYield()
    {
        //%%%You will implement this method
    }//syscallYield
    
    /**
     * selectBlockedProcess
     *
     * select a process to unblock that might be waiting to perform a given
     * action on a given device.  This is a helper method for system calls
     * and interrupts that deal with devices.
     *
     * @param dev   the Device that the process must be waiting for
     * @param op    the operation that the process wants to perform on the
     *              device.  Use the SYSCALL constants for this value.
     * @param addr  the address the process is reading from.  If the
     *              operation is a Write or Open then this value can be
     *              anything
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
    
    
    
	@Override
	public void interruptIllegalMemoryAccess(int addr) {
		System.out.println("Illegal Memory Access!");
        System.exit(0);
		
	}

	@Override
	public void interruptDivideByZero() {
		System.out.println("Divide by Zero Error!");
        System.exit(0);
		
	}

	@Override
	public void interruptIllegalInstruction(int[] instr) {
		System.out.println("Illegal Intruction!");
        System.exit(0);
		
	}
	
	//======================================================================
    // Inner Classes
    //----------------------------------------------------------------------

    /**
     * class ProcessControlBlock
     *
     * This class contains information about a currently active process.
     */
    private class ProcessControlBlock
    {
        /**
         * a unique id for this process
         */
        private int processId = 0;

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
         * save
         *
         * saves the current CPU registers into this.registers
         *
         * @param cpu  the CPU object to save the values from
         */
        public void save(CPU cpu)
        {
            int[] regs = cpu.getRegisters();
            this.registers = new int[CPU.NUMREG];
            for(int i = 0; i < CPU.NUMREG; i++)
            {
                this.registers[i] = regs[i];
            }
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
            int[] regs = cpu.getRegisters();
            for(int i = 0; i < CPU.NUMREG; i++)
            {
                regs[i] = this.registers[i];
            }

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
            blockedForDevice = null;
            blockedForOperation = -1;
            blockedForAddr = -1;
            
        }//block
        
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
         * toString       **DEBUGGING**
         *
         * @return a string representation of this class
         */
        public String toString()
        {
            String result = "Process id " + processId + " ";
            if (isBlocked())
            {
                result = result + "is BLOCKED: ";
            }
            else if (this == m_currProcess)
            {
                result = result + "is RUNNING: ";
            }
            else
            {
                result = result + "is READY: ";
            }

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

    }//class ProcessControlBlock

        
    }//class ProcessControlBlock

    /**
     * class DeviceInfo
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
    


    
};//class SOS
