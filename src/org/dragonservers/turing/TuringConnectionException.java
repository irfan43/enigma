package org.dragonservers.turing;

public class TuringConnectionException extends IllegalArgumentException {
	private final String message;

	public TuringConnectionException(String msg) {
		message = msg;

	}

	@Override
	public String getMessage() {
		return message;
	}

}
