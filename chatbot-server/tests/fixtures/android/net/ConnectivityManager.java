package android.net;

/** Minimal stub of android.net.ConnectivityManager for off-device harnesses. */
public class ConnectivityManager {
    public static class NetworkCallback {
    }

    public void requestNetwork(NetworkRequest request, NetworkCallback callback) {
    }

    public void unregisterNetworkCallback(NetworkCallback callback) {
    }
}
