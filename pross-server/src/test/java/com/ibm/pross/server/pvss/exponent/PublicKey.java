package com.ibm.pross.server.pvss.exponent;

import java.io.Serializable;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;

public class PublicKey implements Serializable {

	private static final long serialVersionUID = 9182993472500674033L;
	
	private final EcPoint Y1;
	private final EcPoint Y2;
	
	public PublicKey(final EcPoint Y1, final EcPoint Y2) {
		this.Y1 = Y1;
		this.Y2 = Y2;
	}

	public EcPoint getY1() {
		return Y1;
	}

	public EcPoint getY2() {
		return Y2;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((Y1 == null) ? 0 : Y1.hashCode());
		result = prime * result + ((Y2 == null) ? 0 : Y2.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		PublicKey other = (PublicKey) obj;
		if (Y1 == null) {
			if (other.Y1 != null)
				return false;
		} else if (!Y1.equals(other.Y1))
			return false;
		if (Y2 == null) {
			if (other.Y2 != null)
				return false;
		} else if (!Y2.equals(other.Y2))
			return false;
		return true;
	}
	
	
}
