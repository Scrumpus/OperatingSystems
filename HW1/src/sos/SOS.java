package sos;

import java.util.*;

/**
 * This class contains the simulated operating system (SOS).  Realistically it
 * would run on the same processor (CPU) that it is managing but instead it uses
 * the real-world processor in order to allow a focus on the essentials of
 * operating system design using a high level programming language.
 *
 * @authors harber14, schwalbe15
 */


public class SOS implements CPU.TrapHandler
{
    //======================================================================
    //Member variables
    //----------------------------------------------------------------------
  //These constants define the system calls this OS can currently handle
    public static final int SYSCALL_EXIT = 0;    /* exit the current program */
    public static final int SYSCALL_OUTPUT = 1;    /* outputs a number */
    public static final int SYSCALL_GETPID = 2;    /* get current process id */
    public static final int SYSCALL_COREDUMP = 9;    /* print process state and exit */
    public static final int SYSCALL_OPEN    = 3;    /* access a device */
    public static final int SYSCALL_CLOSE   = 4;    /* release a device */
    public static final int SYSCALL_READ    = 5;    /* get input from device */
    public static final int SYSCALL_WRITE   = 6;    /* send output to device */
    
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
    
    /*======================================================================
     * Process Management Methods
     *----------------------------------------------------------------------
     */

    //None yet!
    
    /*======================================================================
     * Program Management Methods
     *----------------------------------------------------------------------
     */

    /**
     * Loads a set of program instructions from RAM to execute. This method also sets the
     * base, limit, PC and SP.
     * @param prog the program to be executed
     * @param allocSize the allocated size for the program in main memory
     **/
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
        
        m_CPU.setSP(m_CPU.getBASE() + allocSize - stackSize); //stack grows down
        
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
    
    /**
     *  This method determines which system call has been
     *  invoked and calls the appropriate handler method in 
     *  order to execute the system call
     **/
    public void systemCall()
    {
       int sysCall;
       sysCall = m_CPU.pop(); //get syscall identifier
       switch(sysCall)
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
           
           case SYSCALL_COREDUMP:    
               syscallCoreDump();
               break;
       }//switch
       
    }//SystemCall
    
    
    /**
     * System call to exit a process
     **/
    public void syscallExit()
    {
        System.exit(0);
    }
    
    /**
     * System call for printing value to console
     **/
    public void syscallOutput()
    {
        int output = m_CPU.pop();
        System.out.println("OUTPUT: " + output);
    }
    
    /**
     * System call to get process ID 
     **/
    public void syscallGetPID()
    {
        m_CPU.push(42); //dummy code
    }
    
    /**
     * System call when process reaches fatal error state 
     **/
    public void syscallCoreDump() {
        m_CPU.regDump(); //print current value of process' registers
        System.out.println(m_CPU.pop());
        System.out.println(m_CPU.pop());
        System.out.println(m_CPU.pop());
        syscallExit(); //exit process
    }

    /**
     * Illegal Memory Access Interrupt handler method that prints an 
     * error message and then makes a call to exit.
     * @param addr The address that is out of bounds
     **/
    @Override
    public void interruptIllegalMemoryAccess(int addr) {
        System.out.println("ERROR: ILLEGAL MEMORY ACCESS");
        System.exit(0);
    }

    /**
     * Divide by Zero Interrupt handler method that prints an error 
     * message and then makes a call to exit.
     **/
    @Override
    public void interruptDivideByZero() {
        System.out.println("ERROR: DIVIDE BY ZERO");
        System.exit(0);
    }

    /**
     * Illegal Instruction Interrupt handler method that prints an 
     * error message and then makes a call to exit.
     * @param instr the offending instruction
     **/
    @Override
    public void interruptIllegalInstruction(int[] instr) {
        System.out.println("ERROR: ILLEGAL INSTRUCTION");
        System.exit(0);
    }
    
};//class SOS
