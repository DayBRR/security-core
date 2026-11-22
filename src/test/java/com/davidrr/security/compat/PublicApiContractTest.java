package com.davidrr.security.compat;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.lang.invoke.MethodType;
import java.lang.reflect.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.jar.JarFile;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** One extractor for the pinned reference, JUnit check and standalone ABI verifier. */
public class PublicApiContractTest {
    private static final String HASH = "8d42c42359160d48dd79b6d1f5b042dd8a7b3d9e37ac5a1ab6ed3a2d9f3f4e22";
    private static final String PREFIX = "com/davidrr/security/";
    private static final Set<String> APPROVED_NEW_TYPES = Stream.concat(
            Stream.of("SecurityIdentity", "SecurityRevision", "AdmissionState", "AccountSecuritySnapshot", "AccountSecurityPort",
                    "AccountSecurityPolicy", "TokenAccountClaims", "SecurityValidationFailure", "SecurityValidationException", "AccountSecurityGate")
                    .map(n -> "com.davidrr.security.account." + n),
            Stream.of("JwtReadLimits", "JwtVerificationPolicy", "TrustedJwtKeySource", "VerifiedJwtClaims", "JwtClaimsCodec",
                    "StrictIdentityClaimsCodec", "JwtCryptographicVerifier", "VerifiedAccessIdentity", "AuthoritativeAccessTokenVerifier")
                    .map(n -> "com.davidrr.security.jwt.authoritative." + n)).collect(java.util.stream.Collectors.toUnmodifiableSet());
    private static final String IDENTIFIER = "\\p{javaJavaIdentifierStart}\\p{javaJavaIdentifierPart}*";
    private static final String TYPE_NAME = IDENTIFIER + "(?:\\." + IDENTIFIER + ")*";
    private static final java.util.regex.Pattern TYPE_HEADER = java.util.regex.Pattern.compile(
            "^(?:(?:public|protected|abstract|final|static|strictfp)\\s+)*"
                    + "(?:class|interface|enum|record|@interface)\\s+(" + TYPE_NAME + ")"
                    + "(?:\\s+extends\\s+" + TYPE_NAME + "(?:,\\s*" + TYPE_NAME + ")*)?"
                    + "(?:\\s+implements\\s+" + TYPE_NAME + "(?:,\\s*" + TYPE_NAME + ")*)?$");

    @Test
    void declaredTypeOwnsHeaderAndMembersWhenImplementingPublicInterface() {
        String contract = "com.davidrr.security.auth.service.AuthService";
        String implementation = "com.davidrr.security.auth.service.impl.AuthServiceImpl";
        String output = "public interface " + contract + " {\n"
                + "  public abstract void logout(java.lang.String);\n    descriptor: (Ljava/lang/String;)V\n}\n"
                + "public class " + implementation + " implements " + contract + " {\n"
                + "  public " + implementation + "();\n    descriptor: ()V\n"
                + "  public void logout(java.lang.String);\n    descriptor: (Ljava/lang/String;)V\n}\n";
        SortedSet<String> parsed = parseJavap(output, Set.of(contract, implementation));
        assertEquals(new TreeSet<>(Set.of(
                contract + " | JAVAP public interface " + contract,
                contract + " | JAVAP public abstract void logout(java.lang.String); | descriptor: (Ljava/lang/String;)V",
                implementation + " | JAVAP public class " + implementation + " implements " + contract,
                implementation + " | JAVAP public " + implementation + "(); | descriptor: ()V",
                implementation + " | JAVAP public void logout(java.lang.String); | descriptor: (Ljava/lang/String;)V")),
                parsed);
        Set<String> reflected = Set.of(
                contract + " | METHOD logout (Ljava/lang/String;)V modifiers=1025",
                implementation + " | CTOR ()V modifiers=1",
                implementation + " | METHOD logout (Ljava/lang/String;)V modifiers=1");
        verifyMemberOwners(parsed, reflected);
        SortedSet<String> wrongOwner = new TreeSet<>();
        parsed.forEach(line -> wrongOwner.add(line.replace(implementation + " |", contract + " |")));
        assertThrows(IllegalStateException.class, () -> verifyMemberOwners(wrongOwner, reflected));
    }

    @Test
    void resolvesGenericAndNestedDeclaredTypesIndependentlyOfMentionedTypes() {
        Set<String> types = Set.of("fixture.Implementation", "fixture.Contract", "fixture.Base", "fixture.Outer$Nested");
        assertEquals("fixture.Implementation", declaredOwner(
                "public class fixture.Implementation<T extends fixture.Contract> extends fixture.Base<fixture.Contract> implements fixture.Contract", types));
        assertEquals("fixture.Outer$Nested", declaredOwner(
                "public static class fixture.Outer$Nested<T extends fixture.Base<fixture.Contract>> implements fixture.Contract", types));
        assertEquals("fixture.Contract", declaredOwner("public interface fixture.Contract<T> extends fixture.Base<T>", types));
    }

    @Test
    void rejectsUnknownAmbiguousAndMalformedHeaders() {
        Set<String> types = Set.of("fixture.Known", "fixture.Other");
        for (String header : List.of(
                "public class fixture.Unknown implements fixture.Known",
                "public class fixture.Known class fixture.Other",
                "public class fixture.Known<T extends fixture.Other",
                "public class fixture.Known> implements fixture.Other",
                "public class fixture.Known implements",
                "public fixture.Known")) {
            assertThrows(IllegalStateException.class, () -> declaredOwner(header, types), header);
        }
    }

    @Test
    void rejectsDuplicateMissingAndUnscopedJavapBlocks() {
        String block = "public class fixture.Known {\n}\n";
        assertThrows(IllegalStateException.class, () -> parseJavap(block + block, Set.of("fixture.Known")));
        assertThrows(IllegalStateException.class, () -> parseJavap(block, Set.of("fixture.Known", "fixture.Other")));
        assertThrows(IllegalStateException.class, () -> parseJavap("  public void run();\n    descriptor: ()V\n", Set.of("fixture.Known")));
        assertThrows(IllegalStateException.class, () -> parseJavap("public class fixture.Known {\n  public void run();\n}\n", Set.of("fixture.Known")));
        assertThrows(IllegalStateException.class, () -> parseJavap("public class fixture.Known {\n", Set.of("fixture.Known")));
    }

    @Test
    void completePublicAndProtectedSurfaceMatchesOriginal040() throws Exception {
        requireJava17();
        Path candidate = Path.of(System.getProperty("basedir", "."), "target", "classes").toRealPath();
        Path loadedOrigin = Path.of(Class.forName("com.davidrr.security.auth.service.AuthService")
                .getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
        if (!candidate.equals(loadedOrigin)) throw new AssertionError("JUnit must load candidate classes");
        String reference;
        try (var input = getClass().getResourceAsStream("/compat/security-core-0.4.0-public-api.txt")) {
            if (input == null) throw new AssertionError("Missing original API manifest");
            reference = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        String additions;
        try (var input = getClass().getResourceAsStream("/compat/sec001-03-approved-api-additions.txt")) {
            if (input == null) throw new AssertionError("Missing reviewed additions inventory");
            additions = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        compareAdditive(reference, additions, snapshot(candidate, externalClasspath()), "candidate");
    }

    /** snapshot prints only a hash-pinned baseline; verify never rewrites expectations. */
    public static void main(String[] args) throws Exception {
        requireJava17();
        if (args.length == 3 && args[0].equals("snapshot")) {
            verifyHash(Path.of(args[1]));
            System.out.print(snapshot(Path.of(args[1]), args[2]));
            verifyHash(Path.of(args[1]));
        } else if ((args.length == 5 || args.length == 6) && args[0].equals("verify")) {
            Path baseline = Path.of(args[1]);
            verifyHash(baseline);
            String expected = Files.readString(Path.of(args[4]), StandardCharsets.UTF_8);
            compare(expected, snapshot(baseline, args[3]), "original baseline");
            String candidate = snapshot(Path.of(args[2]), args[3]);
            if (args.length == 6) compareAdditive(expected, Files.readString(Path.of(args[5]), StandardCharsets.UTF_8), candidate, "candidate");
            else compare(expected, candidate, "candidate");
            verifyHash(baseline);
            System.out.println("API/ABI PASS: original hash verified; legacy surface preserved; additions explicitly checked");
        } else {
            throw new IllegalArgumentException("Expected snapshot baseline dependencies OR verify baseline candidate dependencies manifest [additions]");
        }
    }

    private static void requireJava17() {
        if (Runtime.version().feature() != 17) throw new IllegalStateException("JDK 17 required");
    }

    private static void verifyHash(Path baseline) throws Exception {
        String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(baseline)));
        if (!HASH.equals(actual)) throw new IllegalStateException("Original baseline SHA-256 mismatch");
    }

    private static String externalClasspath() {
        return String.join(File.pathSeparator, Arrays.stream(System.getProperty("java.class.path").split(File.pathSeparator))
                .filter(p -> p.endsWith(".jar")).toList());
    }

    private static boolean exported(int modifiers) {
        return Modifier.isPublic(modifiers) || Modifier.isProtected(modifiers);
    }

    private static String snapshot(Path artifact, String dependencies) throws Exception {
        artifact = artifact.toRealPath();
        List<String> names;
        if (Files.isDirectory(artifact)) {
            try (Stream<Path> files = Files.walk(artifact.resolve(PREFIX))) {
                Path root = artifact;
                names = files.filter(p -> p.toString().endsWith(".class"))
                        .map(p -> root.relativize(p).toString().replace('\\', '/')).sorted().toList();
            }
        } else {
            try (JarFile jar = new JarFile(artifact.toFile())) {
                names = jar.stream().map(e -> e.getName())
                        .filter(n -> n.startsWith(PREFIX) && n.endsWith(".class")).sorted().toList();
            }
        }
        if (names.isEmpty()) throw new IllegalStateException("No Security Core classes found");
        List<URL> urls = new ArrayList<>();
        urls.add(artifact.toUri().toURL());
        for (String entry : dependencies.split(File.pathSeparator)) {
            if (!entry.isBlank()) urls.add(Path.of(entry).toUri().toURL());
        }
        SortedSet<String> lines = new TreeSet<>();
        List<String> publicNames = new ArrayList<>();
        // Platform parent prevents the verifier's own candidate classes leaking into the reference.
        try (URLClassLoader loader = new URLClassLoader(urls.toArray(URL[]::new), ClassLoader.getPlatformClassLoader())) {
            for (String entry : names) {
                String name = entry.substring(0, entry.length() - 6).replace('/', '.');
                Class<?> type = Class.forName(name, false, loader);
                if (!Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath().equals(artifact)) {
                    throw new IllegalStateException("Mixed Security Core origins: " + name);
                }
                if (!exported(type.getModifiers())) continue;
                publicNames.add(name);
                lines.add(name + " | CLASS modifiers=" + type.getModifiers());
                for (Field field : type.getDeclaredFields()) {
                    if (exported(field.getModifiers())) lines.add(name + " | FIELD " + field.getName()
                            + " " + field.getType().descriptorString() + " modifiers=" + field.getModifiers());
                }
                for (Constructor<?> ctor : type.getDeclaredConstructors()) {
                    if (exported(ctor.getModifiers())) lines.add(name + " | CTOR "
                            + MethodType.methodType(void.class, ctor.getParameterTypes()).descriptorString()
                            + " modifiers=" + ctor.getModifiers());
                }
                for (Method method : type.getDeclaredMethods()) {
                    if (exported(method.getModifiers())) lines.add(name + " | METHOD " + method.getName() + " "
                            + MethodType.methodType(method.getReturnType(), method.getParameterTypes()).descriptorString()
                            + " modifiers=" + method.getModifiers());
                }
                if (type.isRecord()) {
                    int index = 0;
                    for (RecordComponent component : type.getRecordComponents()) lines.add(name + " | RECORD "
                            + index++ + " " + component.getName() + " " + component.getGenericType().getTypeName());
                }
                if (type.isEnum()) lines.add(name + " | ENUM_ORDER " + Arrays.toString(Arrays.stream(type.getEnumConstants())
                        .map(value -> ((Enum<?>) value).name()).toArray(String[]::new)));
            }
        }
        // javap adds generic signatures, throws clauses, superclasses/interfaces and constant values.
        List<String> command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "javap").toString(),
                "-protected", "-s", "-constants", "-classpath", artifact + File.pathSeparator + dependencies));
        command.addAll(publicNames);
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (process.waitFor() != 0) throw new IllegalStateException("javap failed extracting exported API");
        SortedSet<String> parsed = parseJavap(output, Set.copyOf(publicNames));
        verifyMemberOwners(parsed, lines);
        lines.addAll(parsed);
        return "# Security Core 0.4.0 original public/protected API; JDK 17\n# SHA-256 " + HASH
                + "\n# Generated only from verified original JAR. Sorted declarations; no private members.\n"
                + String.join("\n", lines) + "\n";
    }

    private static String declaredOwner(String header, Set<String> publicNames) {
        // Remove balanced type arguments before parsing the complete declaration grammar.
        // The owner is ONLY the name immediately following class/interface, never a referenced type.
        StringBuilder erased = new StringBuilder();
        int depth = 0;
        for (char ch : header.toCharArray()) {
            if (ch == '<') depth++;
            else if (ch == '>') {
                if (--depth < 0) throw new IllegalStateException("Unbalanced javap type arguments");
            } else if (depth == 0) erased.append(ch);
        }
        if (depth != 0) throw new IllegalStateException("Unbalanced javap type arguments");
        var match = TYPE_HEADER.matcher(erased.toString());
        if (!match.matches()) throw new IllegalStateException("Malformed or ambiguous javap header");
        String owner = match.group(1);
        if (!publicNames.contains(owner)) throw new IllegalStateException("Unknown declared javap type: " + owner);
        return owner;
    }

    private static SortedSet<String> parseJavap(String output, Set<String> publicNames) {
        SortedSet<String> lines = new TreeSet<>();
        Set<String> seen = new HashSet<>();
        String owner = null;
        String declaration = null;
        for (String raw : output.split("\\R")) {
            // Preserve whitespace inside String constant literals: it is part of their value.
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("Compiled from ")) continue;
            if (line.equals("}")) {
                if (owner == null || declaration != null) throw new IllegalStateException("Incomplete javap block");
                owner = null;
                continue;
            }
            if (!raw.startsWith(" ") && line.endsWith("{")) {
                if (owner != null || declaration != null) throw new IllegalStateException("Overlapping javap blocks");
                String header = line.substring(0, line.length() - 1).trim();
                owner = declaredOwner(header, publicNames);
                if (!seen.add(owner)) throw new IllegalStateException("Duplicate javap header: " + owner);
                lines.add(owner + " | JAVAP " + header);
            } else if (line.startsWith("descriptor:")) {
                if (owner == null || declaration == null) throw new IllegalStateException("Unpaired JVM descriptor");
                lines.add(owner + " | JAVAP " + declaration + " | " + line);
                declaration = null;
            } else if (line.endsWith(";")) {
                if (owner == null || declaration != null) throw new IllegalStateException("Unscoped declaration or missing JVM descriptor");
                declaration = line;
            } else {
                throw new IllegalStateException("Unexpected javap output");
            }
        }
        if (owner != null || declaration != null || publicNames.isEmpty() || !seen.equals(publicNames))
            throw new IllegalStateException("Incomplete exported surface");
        return lines;
    }

    private static void verifyMemberOwners(Set<String> parsed, Set<String> reflected) {
        Set<String> expected = new TreeSet<>();
        for (String line : reflected) {
            if (line.contains(" | CTOR ") || line.contains(" | METHOD ") || line.contains(" | FIELD "))
                expected.add(line.substring(0, line.indexOf(" modifiers=")));
        }
        Set<String> actual = new TreeSet<>();
        for (String line : parsed) {
            int descriptorStart = line.indexOf(" | descriptor: ");
            if (descriptorStart < 0) continue;
            int ownerEnd = line.indexOf(" | JAVAP ");
            String owner = line.substring(0, ownerEnd);
            String declaration = line.substring(ownerEnd + " | JAVAP ".length(), descriptorStart);
            String descriptor = line.substring(descriptorStart + " | descriptor: ".length());
            if (descriptor.startsWith("(")) {
                String beforeParameters = declaration.substring(0, declaration.indexOf('('));
                String name = beforeParameters.substring(beforeParameters.lastIndexOf(' ') + 1);
                actual.add(owner + (name.equals(owner) ? " | CTOR " : " | METHOD " + name + " ") + descriptor);
            } else {
                String field = declaration.split(" = ", 2)[0].replaceFirst(";$", "");
                actual.add(owner + " | FIELD " + field.substring(field.lastIndexOf(' ') + 1) + " " + descriptor);
            }
        }
        if (!actual.equals(expected)) throw new IllegalStateException("javap member owners/descriptors disagree with reflection");
    }

    private static void compare(String expected, String actual, String label) {
        if (!expected.replace("\r\n", "\n").equals(actual)) {
            Set<String> missing = new TreeSet<>(expected.lines().toList());
            missing.removeAll(actual.lines().toList());
            Set<String> added = new TreeSet<>(actual.lines().toList());
            added.removeAll(expected.lines().toList());
            throw new AssertionError("Exported API differs for " + label + "; missing/changed=" + missing + "; added/changed=" + added
                    + ". No unreviewed compatibility exceptions are allowed.");
        }
    }

    private static SortedSet<String> declarations(String text) {
        SortedSet<String> result = new TreeSet<>();
        for (String line : text.replace("\r\n", "\n").lines().toList()) {
            if (line.startsWith("#")) continue;
            if (line.isBlank() || !line.equals(line.strip()) || !line.contains(" | ") || !result.add(line)) {
                throw new AssertionError("Malformed or duplicate API inventory declaration");
            }
        }
        return result;
    }

    private static void compareAdditive(String baseline, String additions, String candidate, String label) {
        String header = "# SEC-001-03A reviewed public/protected API additions; JDK 17\n# Baseline SHA-256 " + HASH + "\n";
        if (!additions.replace("\r\n", "\n").startsWith(header)) throw new AssertionError("Unreviewed additions header");
        SortedSet<String> b = declarations(baseline), a = declarations(additions), c = declarations(candidate);
        if (a.isEmpty() || !Collections.disjoint(a,b)) throw new AssertionError("Empty or overlapping additions");
        Set<String> oldOwners = b.stream().map(line -> line.substring(0,line.indexOf(" | "))).collect(java.util.stream.Collectors.toSet());
        for (String line : a) {
            String owner = line.substring(0,line.indexOf(" | "));
            if (!APPROVED_NEW_TYPES.contains(owner) || oldOwners.contains(owner)) throw new AssertionError("Addition outside approved new types");
        }
        SortedSet<String> missing = new TreeSet<>(b); missing.removeAll(c);
        SortedSet<String> delta = new TreeSet<>(c); delta.removeAll(b);
        if (!missing.isEmpty() || !delta.equals(a)) throw new AssertionError("API difference for " + label
                + "; missing/changed=" + missing + "; unexpected/absent approved additions");
    }

    @Test
    void additiveComparisonAllowsOnlyExactReviewedNewDeclarations() {
        String old = "fixture.Legacy | CLASS modifiers=1\nfixture.Legacy | METHOD run ()V modifiers=1\n";
        String added = "com.davidrr.security.account.SecurityIdentity | CLASS modifiers=17\n";
        String header = "# SEC-001-03A reviewed public/protected API additions; JDK 17\n# Baseline SHA-256 " + HASH + "\n";
        assertDoesNotThrow(() -> compareAdditive(old,header+added,old+added,"fixture"));
        assertThrows(AssertionError.class, () -> compareAdditive(old,header+added,old,"fixture"));
        assertThrows(AssertionError.class, () -> compareAdditive(old,header,old,"fixture"));
        assertThrows(AssertionError.class, () -> compareAdditive(old,header+added+added,old+added,"fixture"));
        assertThrows(AssertionError.class, () -> compareAdditive(old,header+added+"fixture.Other | CLASS modifiers=1\n",old+added,"fixture"));
        assertThrows(AssertionError.class, () -> compareAdditive(old,header+added+old,old+added,"fixture"));
        assertThrows(AssertionError.class, () -> compareAdditive(old,header+added,old+added+"fixture.Other | CLASS modifiers=1\n","fixture"));
        assertThrows(AssertionError.class, () -> compareAdditive(old,header+added,old.replace("run", "removed")+added,"fixture"));
        assertThrows(AssertionError.class, () -> compareAdditive(old,header.replace(HASH,"bad")+added,old+added,"fixture"));
        String memberOnLegacy = "fixture.Legacy | METHOD newMethod ()V modifiers=1\n";
        assertThrows(AssertionError.class, () -> compareAdditive(old,header+memberOnLegacy,old+memberOnLegacy,"fixture"));
    }

    @Test
    void additiveInventoryCannotHideChangedLegacyContracts() {
        String header = "# SEC-001-03A reviewed public/protected API additions; JDK 17\n# Baseline SHA-256 " + HASH + "\n";
        String added = "com.davidrr.security.account.SecurityIdentity | CLASS modifiers=17\n";
        for (String declaration : List.of("CLASS modifiers=1", "METHOD protectedCall ()V modifiers=4", "RECORD 0 id java.lang.Long",
                "ENUM_ORDER [FIRST, SECOND]", "JAVAP public class fixture.Legacy extends fixture.Base",
                "JAVAP public java.util.List<java.lang.String> values(); | descriptor: ()Ljava/util/List;",
                "JAVAP public static final java.lang.String CODE = \"ORIGINAL\"; | descriptor: Ljava/lang/String;")) {
            String old = "fixture.Legacy | " + declaration + "\n";
            String changed = "fixture.Legacy | " + declaration + " changed\n";
            assertThrows(AssertionError.class, () -> compareAdditive(old,header+added,changed+added,"fixture"));
            assertThrows(AssertionError.class, () -> compareAdditive(old,header+added+changed,changed+added,"fixture"));
        }
    }
}
