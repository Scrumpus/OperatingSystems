package sos;


/**
 * This class simulates a simple, non-sharable read-only device.  
 *
 */
public class KeyboardDevice implements Device {

	private int m_id = -998;
	
	/**
     * getId
     *
     * @return the device id of this device
     */
	public int getId() {
		return m_id;
	}

	/**
     * setId
     *
     * sets the device id of this device
     *
     * @param id the new id
     */
	public void setId(int id) {
		m_id = id;
	}

	/**
     * isSharable
     *
     * @return true if multiple processes can use the device at once (false for keyboard)
     */
	public boolean isSharable() {
		return false;
	}

	/**
     * isAvailable
     *
     * returns true if the device is available for use
     */
	public boolean isAvailable() {
		return true;
	}

	/**
     * isReadable
     *
     * @return whether this device can be read from (true/false)
     */
	public boolean isReadable() {
		return true;
	}

	/**
     * isWriteable
     *
     * @return whether this device can be written to (true/false)
     */
	public boolean isWriteable() {
		return false;
	}

	/**
     * read
     *
     * method records a request for service from the device and as such is
     * analagous to setting a value in a register on the device's controller.
     */
	public int read(int addr) {
		//for the keyboard, return a random int between 0 and 100
		return (int) (Math.random()*100);
	}

	/**
     * write
     *
     * method records a request for service from the device and as such is
     * analagous to setting a value in a register on the device's controller.
     * As a result, the function does not check to make sure that the
     * device is ready for this request (that's the OS's job).
     */
	public void write(int addr, int data) {
		
	}
	
	
}
