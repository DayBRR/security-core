package com.davidrr.security.auth.util;

public final class UserAgentUtils {

    private UserAgentUtils() {
    }

    public static String toDeviceLabel(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return "Unknown device";
        }

        String ua = userAgent.toLowerCase();

        String client = detectClient(ua);
        String os = detectOs(ua);

        if ("Unknown".equals(client) && "Unknown OS".equals(os)) {
            return "Unknown device";
        }

        if ("Unknown OS".equals(os)) {
            return client;
        }

        if ("Unknown".equals(client)) {
            return os;
        }

        return client + " - " + os;
    }

    private static String detectClient(String ua) {
        if (ua.contains("postmanruntime")) {
            return "Postman";
        }
        if (ua.contains("edg/")) {
            return "Edge";
        }
        if (ua.contains("opr/") || ua.contains("opera")) {
            return "Opera";
        }
        if (ua.contains("chrome/") && !ua.contains("edg/") && !ua.contains("opr/")) {
            return "Chrome";
        }
        if (ua.contains("firefox/")) {
            return "Firefox";
        }
        if (ua.contains("safari/") && !ua.contains("chrome/")) {
            return "Safari";
        }
        if (ua.contains("curl/")) {
            return "cURL";
        }
        if (ua.contains("insomnia")) {
            return "Insomnia";
        }
        if (ua.contains("okhttp")) {
            return "OkHttp";
        }
        if (ua.contains("mozilla/")) {
            return "Browser";
        }
        return "Unknown";
    }

    private static String detectOs(String ua) {
        if (ua.contains("windows")) {
            return "Windows";
        }
        if (ua.contains("android")) {
            return "Android";
        }
        if (ua.contains("iphone") || ua.contains("ipad") || ua.contains("ios")) {
            return "iOS";
        }
        if (ua.contains("mac os x") || ua.contains("macintosh")) {
            return "macOS";
        }
        if (ua.contains("linux")) {
            return "Linux";
        }
        return "Unknown OS";
    }
}