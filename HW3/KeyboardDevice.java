package sos;


/**
 * This class simulates a simple, non-sharable reaad-only device.  
 *
 */
public class KeyboardDevice implements Device {

	private int m_id = -998;
	
	public int getId() {
		return m_id;
	}

	public void setId(int id) {
		m_id = id;
	}

	public boolean isSharable() {
		return false;
	}

	public boolean isAvailable() {
		return true;
	}

	public boolean isReadable() {
		return true;
	}

	public boolean isWriteable() {
		return false;
	}

	public int read(int addr) {
		return (int) (Math.random()*100);
	}

	public void write(int addr, int data) {
		
	}
	
	
}
