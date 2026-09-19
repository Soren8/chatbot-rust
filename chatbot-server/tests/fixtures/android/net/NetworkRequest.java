package android.net;

/** Minimal stub of android.net.NetworkRequest for off-device harnesses. */
public class NetworkRequest {
    public static class Builder {
        public Builder addCapability(int capability) {
            return this;
        }

        public NetworkRequest build() {
            return new NetworkRequest();
        }
    }
}
