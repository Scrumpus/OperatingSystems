package sos;

import java.util.*;

import javax.swing.text.html.MinimalHTMLWriter;

/**
 * This class contains the simulated operating system (SOS).  Realistically it
 * would run on the same processor (CPU) that it is managing but instead it uses
 * the real-world processor in order to allow a focus on the essentials of
 * operating system design using a high level programming language.
 *
 * @authors hollandm15, domingue15, varvel15
 */

public class SOS implements CPU.TrapHandler
{

	//======================================================================
	// Constants
	//----------------------------------------------------------------------

	public static final int SYSCALL_OPEN    = 3;    /* access a device */
	public static final int SYSCALL_CLOSE   = 4;    /* release a device */
	public static final int SYSCALL_READ    = 5;    /* get input from device */
	public static final int SYSCALL_WRITE   = 6;    /* send output to device */

	//These constants define the system calls this OS can currently handle
	public static final int SYSCALL_EXIT     = 0;    /* exit the current program */
	public static final int SYSCALL_OUTPUT   = 1;    /* outputs a number */
	public static final int SYSCALL_GETPID   = 2;    /* get current process id */
	public static final int SYSCALL_COREDUMP = 9;    /* print process state and exit */


	public static final int SYSCALL_EXEC    = 7;    /* spawn a new process */
	public static final int SYSCALL_YIELD   = 8;    /* yield the CPU to another process */

	// These constants define the error codes used by the system handers encounter errors

	public static final int SYSTEM_HANDLER_SUCCESS = 0;
	public static final int DEVICE_NOT_FOUND_ERROR = -1;
	public static final int DEVICE_NOT_SHARABLE_ERROR = -2;
	public static final int DEVICE_ALREADY_OPEN_ERROR = -3;
	public static final int DEVICE_NOT_OPEN_ERROR = -4;
	public static final int DEVICE_READ_ONLY_ERROR = -5;
	public static final int DEVICE_WRITE_ONLY_ERROR = -6;

	/**This process is used as the idle process' id*/
	public static final int IDLE_PROC_ID    = 999;  

	/**Error to indicate an alloc block failed*/
	public static final int ALLOC_BLOCK_FAILED = -1;
	
	//======================================================================
	//Member variables
	//----------------------------------------------------------------------

	/**
	 * This flag causes the SOS to print lots of potentially helpful
	 * status messages
	 **/
	public static final boolean m_verbose = true;
	
	/**
	 * for output that we want to hide from the graders >:)
	 */
	public static final boolean m_debug = false;

	/**
	 * The CPU the operating system is managing.
	 **/
	private CPU m_CPU = null;

	/**
	 * The RAM attached to the CPU.
	 **/
	private RAM m_RAM = null;


	private ProcessControlBlock m_currProcess = null;

	/**
	 * The device attached to the CPU.
	 */
	private Vector<DeviceInfo> m_devices = null;

	/**
	 * All parsed asm files
	 */
	private Vector<Program> m_programs = new Vector<Program>();

	/**
	 * ID of next process created
	 */
	private int m_nextProcessID = 1001;

	/**
	 * List of all processes loaded in ram
	 */
	private Vector<ProcessControlBlock> m_processes = new Vector<ProcessControlBlock>();


	private Vector<MemBlock> m_freeList;

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

		m_currProcess = new ProcessControlBlock(m_nextProcessID);
		m_currProcess.save(m_CPU);
		//		++m_nextProcessID;

		m_devices = new Vector<DeviceInfo>();
		m_freeList = new Vector<MemBlock>();

		//Starting at 0 since it encompasses the entirety of ram
		MemBlock mb = new MemBlock(0, r.getSize());
		m_freeList.add(mb);


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
	 * Process Management Methods
	 *----------------------------------------------------------------------
	 */

	/**
	 * createIdleProcess
	 *
	 * creates a one instruction process that immediately exits.  This is used
	 * to buy time until device I/O completes and unblocks a legitimate
	 * process.
	 *
	 */
	public void createIdleProcess()
	{
		//		debugPrintln("Creating Idle Processs");
		int progArr[] = { 0, 0, 0, 0,   //SET r0=0
				0, 0, 0, 0,   //SET r0=0 (repeated instruction to account for vagaries in student implementation of the CPU class)
				10, 0, 0, 0,   //PUSH r0
				15, 0, 0, 0 }; //TRAP

		//Initialize the starting position for this program
		int baseAddr = allocBlock(progArr.length);

		if (baseAddr == ALLOC_BLOCK_FAILED) {
			System.out.println("AllocBlock Failed for Idle Process");
			System.exit(0);
		}

		//Load the program into RAM
		for(int i = 0; i < progArr.length; i++)
		{
			m_RAM.write(baseAddr + i, progArr[i]);
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
	 * removeCurrentProcess
	 * 
	 * removes the current process from m_processes and randomly selects a new process
	 */
	public void removeCurrentProcess()
	{
		if (m_debug) 
			debugPrintln("The process " + m_currProcess.getProcessId() + " has been removed from RAM");

		m_processes.remove(m_currProcess);
		freeCurrProcessMemBlock();

		//if no other non-blocked process are available then scheduleNewProcess will not
		//overwrite m_currProcess. We will allow m_currProcess to continue running until a
		//new process becomes available. At that point all references to that process should
		//cease to exist and the garbage collector can handle the rest


		scheduleNewProcess();
	}//removeCurrentProcess

	/**
	 * getProcess
	 * 
	 * selects a process to run in a manner to minimize starvation and process switching
	 * 
	 */
	public ProcessControlBlock getProcess() {

		//Always let the idle process finish to avoid extra switching
		if (m_currProcess.getProcessId() == SOS.IDLE_PROC_ID) {
			if (m_processes.contains(m_currProcess)) 
				return m_currProcess;
		}

		ProcessControlBlock selected = null;


		//idle process tick minimization loop
		for (int i = 0; i < m_processes.capacity(); ++i) {

			double minValue = Double.MAX_VALUE;
			for (ProcessControlBlock s : m_processes) {
				if (!s.isBlocked() && s.avgStarve < minValue) {
					selected = s;
					minValue = s.avgStarve + 300;
				}
			}
		}

		return selected;
	}

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

	/**
	 * scheduleNewProcess
	 * 
	 * Checks if a random non-blocked process is available
	 * if it is available then run it
	 * otherwise if no process are available end the simulation
	 */
	public void scheduleNewProcess()
	{

		
		if (m_processes.isEmpty()) {
			System.out.println("No more processes available");
			System.exit(0);
		}
		ProcessControlBlock newProcess = getRandomProcess();
//		ProcessControlBlock newProcess = getProcess();

		if  (m_currProcess != newProcess) {
			m_currProcess.save(m_CPU);

			//If their isn't an unblocked process then make an idle process.
			if (newProcess == null) {
				createIdleProcess();
				return;
			}



			m_currProcess = newProcess;

			m_currProcess.restore(m_CPU);
		}
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

	/*======================================================================
	 * Program Management Methods
	 *----------------------------------------------------------------------
	 */

	/**
	 * createProcess
	 * 
	 * Allocates memory and initializes a process
	 * 
	 * @param prog, the program to that is running the process
	 * @param allocSize, how much memory will this program need
	 */
	public boolean createProcess(Program prog, int allocSize)
	{

		int testProcess[] = prog.export(); //load parsed process

		//TODO: try to figure out what this came from, can we get rid of it? It seems sketchy
		if(prog.getSize() >= allocSize){
			allocSize = prog.getSize()*3; //enlarge allocSize to fit program
		}

		int newMemory = allocBlock(allocSize);

		
		if (newMemory == ALLOC_BLOCK_FAILED) {
			if (m_debug)
				System.out.println("Alloc Block Failed: requires " + allocSize);
			return false;
		}

		//Save register values of the currently running process to somewhere
		m_currProcess.save(m_CPU);
		
		printMemAlloc();

		//Create a new process
		ProcessControlBlock newProcess = new ProcessControlBlock(m_nextProcessID);
		++m_nextProcessID;

		//initialize registers
		m_CPU.setBASE(newMemory); //Set base to arbitrary value (can be changed above)
		m_CPU.setLIM(allocSize); 
		m_CPU.setPC(newMemory); 
		m_CPU.setSP(newMemory + allocSize - 1); 

		//load the program into memory so it can execute
		for(int i = 0; i < testProcess.length; i++){
			m_RAM.write(i + newMemory, testProcess[i]);
		}//for


		m_processes.add(newProcess);
		m_currProcess = newProcess;
		m_currProcess.save(m_CPU);

		if (m_debug)
			debugPrintln("The process " + m_currProcess.getProcessId() + " has been added into RAM");

		return true;

	}//createProcess




	/*======================================================================
	 * System Calls
	 *----------------------------------------------------------------------
	 */


	/**
	 * systemCall
	 * 
	 * Whenever trap is called by assembly code we must read an item off
	 *  the stack and then perform an appropriate system call
	 */
	public void systemCall()
	{

		int syscall_input = m_CPU.pop();

		//See method headers for details of these operations

		switch (syscall_input) {
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
		case SYSCALL_OPEN:
			syscallOpen();
			break;
		case SYSCALL_READ:
			syscallRead();
			break;
		case SYSCALL_CLOSE:
			syscallClose();
			break;
		case SYSCALL_WRITE:
			syscallWrite();
			break;
		case SYSCALL_YIELD:
			syscallYield();
			break;
		case SYSCALL_EXEC:
			syscallExec();
			break;
		default:
			break;
		}

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
		boolean wasSuccesful  = createProcess(prog, allocSize);
		if (wasSuccesful) {
			//Adjust the PC since it's about to be incremented by the CPU
			m_CPU.setPC(m_CPU.getPC() - CPU.INSTRSIZE);
		}
	}//syscallExec


	/**
	 * syscallYield
	 * 
	 * Description: puts the current process to sleep (moves it to the ready state)
	 * 
	 */
	private void syscallYield()
	{
		scheduleNewProcess();
	}//syscallYield


	/**
	 * syscallExit
	 * 
	 * Terminates the program
	 */
	private void syscallExit() {
		removeCurrentProcess();
	}


	/**
	 * syscallOutput
	 * 
	 * Pops an item off the stack and prints it to console
	 */
	private void syscallOutput() {
		int output = m_CPU.pop();

		System.out.println("OUTPUT: " + output);
	}


	/**
	 * syscallGetPID
	 * 
	 * Returns the process id of the system
	 */
	private void syscallGetPID() {
		m_CPU.push(m_currProcess.getProcessId());
	}


	/**
	 * syscallCoreDump
	 * 
	 * calls CPU.regDump, prints the top 3 items on the stack, terminates the program
	 * 
	 */
	private void syscallCoreDump() {
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
	 * syscallOpen
	 * 
	 * Assigns the current process to the device whose id is on the stack.
	 * 
	 * If the operation is not successful it will push an error code to the stack,
	 * otherwise it will push a success code.
	 */
	private void syscallOpen() {
		int deviceNum = m_CPU.pop();
		DeviceInfo deviceInfo = getDeviceInfo(deviceNum);

		//check that the device exists
		if (deviceInfo == null) {
			m_CPU.push(DEVICE_NOT_FOUND_ERROR);
			return;
		}

		//check that the device is not already open
		if (deviceInfo.containsProcess(m_currProcess)) {
			m_CPU.push(DEVICE_ALREADY_OPEN_ERROR);
			return;
		}

		//check that the device is sharable and if not then check that it's not already open
		if (!deviceInfo.getDevice().isSharable() && !deviceInfo.unused()) {
			
			deviceInfo.addProcess(m_currProcess);
			debugPrintln("Blocked Process " + m_currProcess.getProcessId() + " on device " + deviceInfo.getId());
			debugPrintln(m_currProcess.toString());
			//address is left as zero since it doesn't apply to opening a device (I think)
			m_currProcess.block(m_CPU, deviceInfo.getDevice(), SYSCALL_OPEN, 0);

			m_CPU.push(SYSTEM_HANDLER_SUCCESS);

			scheduleNewProcess();
			return;
		}


		//		debugPrintln("Process " + m_currProcess.getProcessId() + " opened device " + deviceNum);

		deviceInfo.addProcess(m_currProcess);
		m_CPU.push(SYSTEM_HANDLER_SUCCESS);
	}


	/**
	 * syscallClose
	 * 
	 * Removes the current process from the device whose id is on the stack.
	 * 
	 * If the operation is not successful it will push an error code to the stack,
	 * otherwise it will push a success code.
	 */
	private void syscallClose() {
		int deviceNum = m_CPU.pop();
		DeviceInfo deviceInfo = getDeviceInfo(deviceNum);

		//check that the device exists
		if (deviceInfo == null) {
			m_CPU.push(DEVICE_NOT_FOUND_ERROR);
			return;
		}

		//Check that device is not already open
		if (!deviceInfo.containsProcess(m_currProcess)) {
			m_CPU.push(DEVICE_NOT_OPEN_ERROR);
			return;
		}

		deviceInfo.removeProcess(m_currProcess);

		ProcessControlBlock blockedProcess = selectBlockedProcess(deviceInfo.getDevice(), SYSCALL_OPEN, 0);
		//Again addr is left as 0 since as far as I can tell it does not apply


		//		debugPrintln("Process " + m_currProcess.getProcessId() + " closed device " + deviceNum);

		if (blockedProcess != null) {
			blockedProcess.unblock();

			//			debugPrintln("Process " + blockedProcess.getProcessId() + " opened device " + deviceNum);
		} else {
//			System.out.print("");
		}


		m_CPU.push(SYSTEM_HANDLER_SUCCESS);
	}


	/**
	 * syscallWrite
	 * 
	 * pops data, address, and device id off the stack (in that order)
	 * writes to the device
	 * 
	 * If the operation is not successful it will push an error code to the stack,
	 * otherwise it will push a success code
	 * 
	 */
	private void syscallWrite() {

		int data = m_CPU.pop();
		int addr = m_CPU.pop();

		int deviceNum = m_CPU.pop();
		DeviceInfo devInfo = getDeviceInfo(deviceNum);

		//check that the device exists
		if (devInfo == null) {
			m_CPU.push(DEVICE_NOT_FOUND_ERROR);
			return;
		}

		//Called after if  to prevent a method call on a null object
		Device dev = devInfo.getDevice();

		//Check that device is not already open
		if (!devInfo.containsProcess(m_currProcess)) {
			m_CPU.push(DEVICE_NOT_OPEN_ERROR);
			return;
		}

		//Check that the device is not read only
		if (!dev.isWriteable()) {
			m_CPU.push(DEVICE_READ_ONLY_ERROR);
			return;
		}


		if (!dev.isAvailable()) {
			m_CPU.push(deviceNum);
			m_CPU.push(addr);
			m_CPU.push(data);
			m_CPU.push(SOS.SYSCALL_WRITE);
			m_CPU.setPC(m_CPU.getPC() - CPU.INSTRSIZE);
			if (m_debug)
				debugPrintln("Process id " + m_currProcess.getProcessId() + " is now ready");

			scheduleNewProcess();
			return;
		}

		//Block the process
		this.m_currProcess.save(m_CPU);
		this.m_currProcess.block(m_CPU, dev, SOS.SYSCALL_WRITE, addr);

		dev.write(addr, data);

		scheduleNewProcess();

	}

	/**
	 * syscallRead
	 * 
	 * pops address and device id off the stack (in that order)
	 * reads from the device
	 * 
	 * If the operation is not successful it will push an error code to the stack,
	 * otherwise it will push a success code
	 */
	private void syscallRead() {


		int addr = m_CPU.pop();

		int deviceNum = m_CPU.pop();

		DeviceInfo devInfo = getDeviceInfo(deviceNum);

		//check that the device exists
		if (devInfo == null) {
			m_CPU.push(DEVICE_NOT_FOUND_ERROR);
			return;
		}
		Device dev = devInfo.getDevice();

		//Check that device is already open
		if (!devInfo.containsProcess(m_currProcess)) {
			m_CPU.push(DEVICE_NOT_OPEN_ERROR);
			return;
		}

		//Check that the device is not read only
		if (!dev.isReadable()) {
			m_CPU.push(DEVICE_WRITE_ONLY_ERROR);
			return;
		}

		if (!dev.isAvailable()) {
			m_CPU.push(deviceNum);
			m_CPU.push(addr);
			m_CPU.push(SOS.SYSCALL_READ);
			m_CPU.setPC(m_CPU.getPC() - CPU.INSTRSIZE);
			if (m_debug)
				debugPrintln("Process id " + m_currProcess.getProcessId() + " is now ready");
			scheduleNewProcess();
			return;
		}


		//Block the process
		this.m_currProcess.save(m_CPU);
		this.m_currProcess.block(m_CPU, dev, SOS.SYSCALL_READ, addr);

		dev.read(addr);
		scheduleNewProcess();


	}


	/**
	 * getDevice
	 * 
	 * Helper method to get the device from the list of devices based on its device id.
	 * 
	 * @param deviceId
	 * 
	 * @return the device, null if no device found
	 */
	public DeviceInfo getDeviceInfo(int deviceId) {
		for (DeviceInfo dev : m_devices) {
			if (dev.getId() == deviceId) {
				return dev;
			}
		}

		return null;
	}

	/*======================================================================
	 * Interrupt Handlers
	 *----------------------------------------------------------------------
	 */

	/**
	 * interruptIllegalMemoryAccess
	 * 
	 * When the program tries to get data from outside its designated space close the program.
	 * 
	 * @param addr
	 */
	@Override
	public void interruptIllegalMemoryAccess(int addr) {
		System.out.println("Illegal Memory Access of addr: " + addr + " by proccess " + m_currProcess.getProcessId());
		
		removeCurrentProcess();

	}

	/**
	 * interruptDivideByZero
	 * 
	 * When the program tries to divide by zero close the program.
	 * 
	 */
	@Override
	public void interruptDivideByZero() {
		System.out.println("Divide by Zero Error!");

		removeCurrentProcess();
	}

	/**
	 * interruptIllegalInstruction
	 * 
	 * When the program runs into an illegal instruction close the program.
	 * 
	 */
	@Override
	public void interruptIllegalInstruction(int[] instr) {
		System.out.println("Illegal Intruction!");

		removeCurrentProcess();
	}

	/**
	 * interruptIOReadComplete
	 * 
	 * Description: when a device finishes a read instruction it calls this function to interrupt
	 * 		the currently running process to hand off the read data to the relevant process
	 * 
	 * @param devID - the id of the device that was being written to
	 * @param addr - the address we wrote to
	 * @param data - the data returned from the read
	 */
	@Override
	public void interruptIOReadComplete(int devID, int addr, int data) {

		DeviceInfo devInfo = getDeviceInfo(devID);

		ProcessControlBlock blocked = selectBlockedProcess(devInfo.getDevice(), SYSCALL_READ, addr);

		if (blocked == null) {
			System.out.println("Null blocked process, interruptIOReadComplete");
			
			removeCurrentProcess();
		}

		//		debugPrintln("The process " + m_currProcess.getProcessId() + " has recived an interupt from device " + devID);
		blocked.unblock();

		//Push the data we received from the read to the reading processes stack
		blocked.push(data);

		//Push a successful system call indicator to the reading processes stack
		blocked.push(SOS.SYSTEM_HANDLER_SUCCESS);

	}

	/**
	 * interruptIOWriteComplete
	 * 
	 * Description: when a device finishes a write instruction it calls this function to interrupt
	 * 		the currently running process to notify the relevant process that the operation completed
	 * 
	 * @param devID - the id of the device that was being written to
	 * @param addr - the address we wrote to
	 */
	@Override
	public void interruptIOWriteComplete(int devID, int addr) {
		DeviceInfo devInfo = getDeviceInfo(devID);

		ProcessControlBlock blocked = selectBlockedProcess(devInfo.getDevice(), SYSCALL_WRITE, addr);


		System.out.println("Device Procs Size: "+devInfo.procs.size());
		if (blocked == null) {
			System.out.println("Null blocked process, interruptIOWriteComplete");

			removeCurrentProcess();
		}

		blocked.push(SOS.SYSTEM_HANDLER_SUCCESS);

		blocked.unblock();
	}

	/**
	 * interruptClock
	 * 
	 * schedules a new process
	 */
	public void interruptClock() {
		scheduleNewProcess();
	}

	/*======================================================================
	 * Memory Block Management Methods
	 *----------------------------------------------------------------------
	 */


	/**
	 * allocBlock
	 * 
	 * Description: First Fit. If a contiguous block of memory that is big enough to fit the given size program
	 * 		exists then allocate memory. Otherwise, if the total amount of free space is enough for the program, 
	 * 		compact memory for allocation. If there is not enough free space, failed.
	 * 
	 * @param size how much memory requested
	 * @return the address of the allocated block
	 */
	private int allocBlock(int size)
	{

		if (m_freeList.isEmpty()) {
			return ALLOC_BLOCK_FAILED;
		}

		int totalAvailable = 0;
		int firstEmptyBlock = Integer.MAX_VALUE; //The only way it could keep this value would be that m_freeList is empty

		//Look through free memory blocks looking for one that is big enough to store the program
		MemBlock selected = null;
		for (MemBlock mem : m_freeList) {
			//keep track of how much free memory is available
			totalAvailable += mem.getSize();

			if (firstEmptyBlock > mem.m_addr) {
				firstEmptyBlock = mem.m_addr;
			}

			if (mem.getSize() >= size){
				selected = mem;
				break;
			}
		}

		if (selected == null) {
			//if there is enough room to allocate the space but it isn't contiguous then
			//group all processes together
			if (totalAvailable >= size) {
				if (m_debug)
					System.out.println("can consolidate");
				
				ProcessControlBlock lastBlock = smartMove(firstEmptyBlock);
				
				//This "should" never happen
				if (lastBlock == null) {
					if (m_debug) {
						System.out.println("Fail1");
						printMemAlloc();
					}
					return ALLOC_BLOCK_FAILED;
				}
				
				//Since things are compacted, update m_freelist
				m_freeList.clear();

				//Creates the Memblock for the space after compaction
				int addr = lastBlock.getRegisterValue(CPU.LIM) + lastBlock.getRegisterValue(CPU.BASE);
				int remainingSpace = m_RAM.getSize() - addr;
				MemBlock newMemblock = new MemBlock(addr, remainingSpace);
				m_freeList.add(newMemblock);

				if (m_debug) {
					System.out.println("Finished");
					printMemAlloc();
				}
			
				//recurse to actually allocate the space to the process
				return allocBlock(size);

			} else {
				return ALLOC_BLOCK_FAILED;
			}

		}

		//Space was found in an existing Memblock
		//Update m_freeList
		m_freeList.remove(selected);
		if (m_debug)
			System.out.println("Allocated memory from " + selected.getAddr() + " to " + (selected.getAddr() + size));

		//If it is an exact size then we don't have to add a Memblock
		if (selected.getSize() == size) {
			return selected.getAddr();
		}

		//Create the Memblock for the space that the program did not take up
		int newAddr = selected.m_addr + size;
		int newSize = selected.m_size - size;
		
		if (m_debug)
			System.out.println("Shrinking free memory space from " + selected.getAddr() +"-" + (selected.getAddr() + selected.getSize()) + " to " + newAddr + "-" + (newAddr+newSize));
		MemBlock remaining = new MemBlock(newAddr, newSize);
		m_freeList.add(remaining);

		return selected.getAddr();
	}//allocBlock

	
	/**
	 * getNextProcessInMemory
	 * 
	 * Description: This helper method finds the next process in memory after the given address.
	 * 
	 * @param nextSlotAddress - look for a pcb with base after this index
	 * @return the pcb if there is one, otherwise return null
	 */
	private ProcessControlBlock getNextProcessInMemory(int nextSlotAddress) {
		int nextProcess = Integer.MAX_VALUE;

		
		ProcessControlBlock selected = null;
		for (ProcessControlBlock pcb : m_processes) {
			int base = pcb.getRegisterValue(CPU.BASE);

			if (base < nextSlotAddress) {
				continue;
			}

			if (base < nextProcess ) {
				nextProcess = base;
				selected = pcb;
			}

		}

		return selected;
	}


	/**
	 * smartMove
	 * 
	 * Description: This helper method compacts all the memory
	 * 
	 * @param firstEmptyBlock - shifts processes after this index to this index 
	 * @return the last pcb moved. If there isn't one, return null
	 */
	private ProcessControlBlock smartMove(int firstEmptyBlock) {
		
		ProcessControlBlock nextProcess = null;
		
		//finds the first process after firstEmptyBlock
		nextProcess = getNextProcessInMemory(firstEmptyBlock);

		//Base Case: No more processes after the first empty block
		if (nextProcess == null)
			return null;

		//the location of slot after the process has been shifted
		int emptySlot = firstEmptyBlock + nextProcess.getRegisterValue(CPU.LIM);
		
		int endOfNextProcess = nextProcess.getRegisterValue(CPU.BASE) + nextProcess.getRegisterValue(CPU.LIM);
	
		System.out.println("Moving from " + nextProcess.getRegisterValue(CPU.BASE) + " to " + firstEmptyBlock);
		nextProcess.move(firstEmptyBlock);

		if (m_debug)
			printMemAlloc();
		
		//find the next process to shift
		ProcessControlBlock pcb = getNextProcessInMemory(endOfNextProcess);

		//if there is no more processes to shift, return nextProcess
		if (pcb == null)
			return nextProcess;
		//otherwise shift the next next process
		ProcessControlBlock lastPCB = smartMove(emptySlot);
		
		//if lastPCB is null, then we hit the base case
		if (lastPCB == null)
			return pcb; 
		else
			return lastPCB;
		
	}

	/**
	 * freeCurrProcessMemBlock
	 * 
	 * Description: frees the current process, merges any contiguous MemBlocks
	 * 
	 */
	private void freeCurrProcessMemBlock()
	{

		int start = m_currProcess.getRegisterValue(CPU.BASE);
		int size = m_currProcess.getRegisterValue(CPU.LIM);

		//Create a new Memblock to replace the removed process
		MemBlock newSpace = new MemBlock(start, size);
		m_freeList.add(newSpace);
		
		if (m_debug) {
			System.out.println("Freeing memory from " + start + " to " + (start+size));
			printMemAlloc();
		}
		
		//Iterate through m_freeList to looking for adjacent Memblocks, if found, merge them with
		//the new Memblock and mark them for deletion
		
		Vector<MemBlock> delete = new Vector<SOS.MemBlock>();
		for (MemBlock mem : m_freeList) {

			//a MemBlock exists below to merge with
			if (newSpace.compareTo(mem) == mem.getSize()) {
				newSpace.m_addr = mem.m_addr;
				newSpace.m_size += mem.m_size;
				delete.add(mem);
		
				if (m_debug)
					System.out.println("Merging Down memory blocks " + newSpace.m_addr + " to " + (newSpace.m_addr+newSpace.m_size));
				
			}

			//a MemBlock exists above to merge with
			if (mem.compareTo(newSpace) == newSpace.getSize()) {
				newSpace.m_size += mem.m_size;
				delete.add(mem);				
				if (m_debug)
					System.out.println("Merging Up memory blocks " + newSpace.m_addr + " to " + (newSpace.m_addr+newSpace.m_size));
			}

		}

		//Because we can't delete them while iterating through
		for (MemBlock mem : delete) {
			m_freeList.remove(mem);
		}
		if (m_debug) 
			printMemAlloc();
		
	}//freeCurrProcessMemBlock

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
				System.out.print(" Process " + pi.processId +  " (addr=" + pAddr + ", size=" + size + " words, limit= " + (pAddr + size) + ") ");
				System.out.print(" @BASE=" + m_RAM.read(pi.getRegisterValue(CPU.BASE))
						+ " @SP=" + m_RAM.read(pi.getRegisterValue(CPU.SP)));
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
				System.out.println("    Open(addr=" + mAddr + ", size=" + m.getSize() + " words, limit= " + (mAddr + m.getSize()) + ")");
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

		/** Accessory methods */
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

		/**
		 * The number of ticks that this 
		 */
		private int numStarvationTicks = 0;

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
		 * @return the last time this process was put in the Ready state
		 */
		public long getLastReadyTime()
		{
			return lastReadyTime;
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
			//A context switch is expensive.  We simulate that here by 
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
			//A context switch is expensive.  We simulate that here by 
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

			debugPrintln("Process " + m_currProcess.getProcessId() + " has been blocked while waiting for " + dev.getId());

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
				result = result + "is BLOCKED for ";
				if (blockedForOperation == SYSCALL_OPEN)
				{
					result = result + "OPEN";
				}
				else if (blockedForOperation == SYSCALL_READ)
				{
					result = result + "READ @" + blockedForAddr;
				}
				else if (blockedForOperation == SYSCALL_WRITE)
				{
					result = result + "WRITE @" + blockedForAddr;
				}
				else  
				{
					result = result + "unknown reason!";
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

		/**
		 * push
		 * 
		 * Pushes data to the stack of this process
		 * 
		 * @param data
		 */
		public void push(int data) {
			int sp = getRegisterValue(CPU.SP) - CPU.STACKITEMSIZE;
			setRegisterValue(CPU.SP, sp);
			m_RAM.write(sp, data);
		}

		/**
		 * 
		 * pop
		 * 
		 * Pops data from this processes stack
		 * 
		 * @return
		 */
		public int pop() {
			int sp = getRegisterValue(CPU.SP) + CPU.STACKITEMSIZE;
			setRegisterValue(CPU.SP, sp);
			return m_RAM.read(sp+CPU.STACKITEMSIZE);

		}



		/**
		 * move
		 * 
		 * Description: move this pcb to another point in memory
		 * 
		 * @param newBase - the new location in memory
		 * @return whether or not it was successful
		 */
		public boolean move(int newBase)
		{
			
			if (newBase < 0) {
				//Something bad has happened
				return false;
			}

			if (newBase + getRegisterValue(CPU.LIM) > m_RAM.getSize()) {
				//Something bad has happened
				return false;
			}

			int oldBase = getRegisterValue(CPU.BASE);
			int programSize = getRegisterValue(CPU.LIM);

			//actually move the program
			for (int i = 0; i < programSize; ++i) {

				int newValue = m_RAM.read(oldBase + i);
				m_RAM.write(newBase + i, newValue);
			}

			//update registers saved in pcb
			setRegisterValue(CPU.BASE, newBase);

			int newSP = this.getRegisterValue(CPU.SP) - oldBase + newBase;
			setRegisterValue(CPU.SP, newSP);

			int newPC = this.getRegisterValue(CPU.PC) - oldBase + newBase;
			setRegisterValue(CPU.PC, newPC);

			//if this is the current process then update CPU registers
			if (this == m_currProcess) {
				m_CPU.setBASE(newBase);
				
				newSP = m_CPU.getSP() - oldBase + newBase;
				m_CPU.setPC(newPC);
				
				newPC = m_CPU.getPC() - oldBase + newBase;
				m_CPU.setSP(newSP);
			}

			//limit does not need to be changed since it is a logical address
			
			if (m_debug)
				debugPrintln("Process " + this.getProcessId() + " has moved from " + oldBase + " to " + newBase);

			return true;
		}//move

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
