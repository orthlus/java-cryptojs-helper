package art.aelaort;

public class CryptoJSImplDecryptionException extends RuntimeException {
	public CryptoJSImplDecryptionException(Exception e) {
		super(e);
	}

	public CryptoJSImplDecryptionException(String message) {
		super(message);
	}
}
