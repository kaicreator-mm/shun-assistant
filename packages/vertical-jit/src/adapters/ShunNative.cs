// Shun native Windows safety primitives (T10 / #50 R6).
//
// Compiled at run time by the trusted PowerShell bootstrap (Add-Type, C# 5
// compatible for the Windows PowerShell 5.1 compiler) and provides exactly two
// operations on behalf of the managed-portable vertical:
//
//   Extract    — ZIP extraction through ONE locked archive stream whose SHA is
//                re-verified inside the lock, with every filesystem access
//                performed RELATIVE to pinned native handles: the destination
//                chain is opened component-by-component with
//                FILE_OPEN_REPARSE_POINT from the drive root, every directory
//                component is created/opened relative to its pinned parent and
//                reparse-refused BEFORE a single byte is written, and files are
//                created FILE_CREATE (create-new) on the pinned parent. No open
//                ever re-resolves a path from a string, so a same-user junction
//                swap before or during extraction cannot redirect a write.
//
//   RemoveTree — identity-pinned manifest deletion. The root chain is pinned
//                the same way (reparse anywhere refuses with zero deletion),
//                the census enumerates children through NtQueryDirectoryFile on
//                pinned directory handles and OPENS every object relative to
//                its pinned parent (no-follow), records the NT FileId and
//                content hash, and refuses any object outside the exact
//                manifest (or matching a recorded identity). Objects are then
//                deleted BY HANDLE via FileDispositionInformationEx with POSIX
//                semantics — a same-path replacement between census and delete
//                either hits a FileId re-verification or leaves the replacement
//                behind as retained foreign content; pathname rmdir/unlink is
//                never used.
//
// Deliberately no LINQ, string interpolation or other post-C#5 syntax: the
// stock Windows PowerShell 5.1 compiler must accept this source verbatim.

namespace Shun
{
    public sealed class NativeRefuseException : System.Exception
    {
        public NativeRefuseException(string code) : base(code) { }
        public NativeRefuseException(string code, string detail)
            : base(code + "\t" + detail) { }
    }

    public static class Native
    {
        // ------------------------------------------------------------------
        // interop
        // ------------------------------------------------------------------

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public System.IntPtr Buffer;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public System.IntPtr RootDirectory;
            public System.IntPtr ObjectName;
            public uint Attributes;
            public System.IntPtr SecurityDescriptor;
            public System.IntPtr SecurityQualityOfService;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct IO_STATUS_BLOCK
        {
            public System.IntPtr Information;
            public int Status;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct FILE_ATTRIBUTE_TAG_INFORMATION
        {
            public uint FileAttributes;
            public uint ReparseTag;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct FILE_DISPOSITION_INFORMATION_EX
        {
            public uint Flags;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern System.IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            System.IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            System.IntPtr hTemplateFile);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(System.IntPtr hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(System.IntPtr hObject);

        [System.Runtime.InteropServices.DllImport("ntdll.dll")]
        private static extern int NtCreateFile(
            out System.IntPtr FileHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref IO_STATUS_BLOCK IoStatusBlock,
            System.IntPtr AllocationSize,
            uint FileAttributes,
            uint ShareAccess,
            uint CreateDisposition,
            uint CreateOptions,
            System.IntPtr EaBuffer,
            uint EaLength);

        [System.Runtime.InteropServices.DllImport("ntdll.dll")]
        private static extern int NtQueryInformationFile(
            System.IntPtr FileHandle,
            ref IO_STATUS_BLOCK IoStatusBlock,
            System.IntPtr FileInformation,
            uint Length,
            int FileInformationClass);

        [System.Runtime.InteropServices.DllImport("ntdll.dll")]
        private static extern int NtSetInformationFile(
            System.IntPtr FileHandle,
            ref IO_STATUS_BLOCK IoStatusBlock,
            ref FILE_DISPOSITION_INFORMATION_EX FileInformation,
            uint Length,
            int FileInformationClass);

        [System.Runtime.InteropServices.DllImport("ntdll.dll")]
        private static extern int NtWriteFile(
            System.IntPtr FileHandle,
            System.IntPtr Event,
            System.IntPtr ApcRoutine,
            System.IntPtr ApcContext,
            ref IO_STATUS_BLOCK IoStatusBlock,
            byte[] Buffer,
            uint Length,
            System.IntPtr ByteOffset,
            System.IntPtr Key);

        [System.Runtime.InteropServices.DllImport("ntdll.dll")]
        private static extern int NtQueryDirectoryFile(
            System.IntPtr FileHandle,
            System.IntPtr Event,
            System.IntPtr ApcRoutine,
            System.IntPtr ApcContext,
            ref IO_STATUS_BLOCK IoStatusBlock,
            System.IntPtr FileInformation,
            uint Length,
            int FileInformationClass,
            bool ReturnSingleEntry,
            System.IntPtr FileName,
            bool RestartScan);

        [System.Runtime.InteropServices.DllImport("ntdll.dll")]
        private static extern uint RtlNtStatusToDosError(int Status);

        private const uint GENERIC_READ = 0x80000000;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint DELETE_ACCESS = 0x00010000;
        private const uint FILE_READ_DATA = 0x0001;
        private const uint FILE_READ_ATTRIBUTES = 0x0080;
        private const uint FILE_WRITE_DATA = 0x0002;
        private const uint FILE_SHARE_READ = 0x1;
        private const uint FILE_SHARE_ALL = 0x7;
        private const uint FILE_OPEN = 1;
        private const uint FILE_CREATE = 2;
        private const uint FILE_OPEN_IF = 3;
        private const uint FILE_DIRECTORY_FILE = 0x1;
        private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x20;
        private const uint FILE_NON_DIRECTORY_FILE = 0x40;
        private const uint FILE_OPEN_REPARSE_POINT = 0x200000;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
        private const int FileAttributeTagInformation = 35;
        private const int FileIdInformation = 59;
        private const int FileDispositionInformationEx = 64;
        private const int FileDirectoryInformation = 1;
        private const int STATUS_NO_MORE_FILES = unchecked((int)0x80000006);
        private const int STATUS_OBJECT_NAME_COLLISION = unchecked((int)0xC0000035);
        private const int STATUS_OBJECT_NAME_NOT_FOUND = unchecked((int)0xC0000034);
        private const int STATUS_OBJECT_PATH_NOT_FOUND = unchecked((int)0xC000003A);
        private const uint FILE_DISPOSITION_FLAG_DELETE = 0x1;
        private const uint FILE_DISPOSITION_FLAG_POSIX_SEMANTICS = 0x2;

        // resource budgets (R3/R4 ZIP limits — enforced again on real streams)
        private const int MaxEntries = 4096;
        private const long MaxArchiveBytes = 536870912L;
        private const long MaxEntryBytes = 268435456L;
        private const long MaxExpandedBytes = 1073741824L;
        private const double MaxRatio = 400.0;

        // ------------------------------------------------------------------
        // shared helpers
        // ------------------------------------------------------------------

        private static string Hex(byte[] bytes)
        {
            return System.BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        private static bool IsLowerHex(string value, int length)
        {
            if (value == null || value.Length != length) return false;
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            }
            return true;
        }

        private static string ShaFinal(System.Security.Cryptography.SHA256 sha)
        {
            byte[] empty = new byte[0];
            sha.TransformFinalBlock(empty, 0, 0);
            return Hex(sha.Hash);
        }

        private static void ThrowStatus(string what, string path, int status)
        {
            throw new NativeRefuseException(
                "NATIVE_STATUS",
                what + " " + path + " failed: NTSTATUS=0x" + status.ToString("X8") +
                " Win32=" + RtlNtStatusToDosError(status));
        }

        /// Open `C:\` style drive root with no-reparse semantics.
        private static System.IntPtr OpenDriveRoot(string driveRoot)
        {
            System.IntPtr handle = CreateFileW(
                driveRoot,
                GENERIC_READ | SYNCHRONIZE,
                FILE_SHARE_ALL,
                System.IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_OPEN_REPARSE_POINT,
                System.IntPtr.Zero);
            if (handle == new System.IntPtr(-1))
            {
                throw new NativeRefuseException("ZIP_DEST_MISSING", "drive root " + driveRoot + " cannot be opened");
            }
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(handle, out info))
            {
                CloseHandle(handle);
                throw new NativeRefuseException("ZIP_DEST_MISSING", "drive root " + driveRoot + " cannot be queried");
            }
            if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                CloseHandle(handle);
                throw new NativeRefuseException("ZIP_REPARSE_POINT", "drive root " + driveRoot + " is a reparse point");
            }
            return handle;
        }

        /// Relative, no-follow open of one name under a pinned parent handle.
        /// Every later filesystem access composes from handles returned here,
        /// so pathname re-resolution (and with it the junction-swap race)
        /// never happens between check and effect.
        private static int OpenRelativeCore(
            System.IntPtr parent,
            string name,
            uint desiredAccess,
            uint disposition,
            uint createOptions,
            out System.IntPtr handle)
        {
            return OpenRelativeCoreShared(
                parent, name, desiredAccess, disposition, createOptions, FILE_SHARE_ALL, out handle);
        }

        private static int OpenRelativeCoreShared(
            System.IntPtr parent,
            string name,
            uint desiredAccess,
            uint disposition,
            uint createOptions,
            uint shareAccess,
            out System.IntPtr handle)
        {
            byte[] nameBytes = System.Text.Encoding.Unicode.GetBytes(name);
            System.IntPtr nameBuffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(nameBytes.Length);
            try
            {
                System.Runtime.InteropServices.Marshal.Copy(nameBytes, 0, nameBuffer, nameBytes.Length);
                UNICODE_STRING us;
                us.Length = (ushort)nameBytes.Length;
                us.MaximumLength = (ushort)nameBytes.Length;
                us.Buffer = nameBuffer;
                OBJECT_ATTRIBUTES oa;
                oa.Length = System.Runtime.InteropServices.Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
                oa.RootDirectory = parent;
                oa.ObjectName = System.Runtime.InteropServices.Marshal.AllocHGlobal(System.Runtime.InteropServices.Marshal.SizeOf(typeof(UNICODE_STRING)));
                System.Runtime.InteropServices.Marshal.StructureToPtr(us, oa.ObjectName, false);
                oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
                oa.SecurityDescriptor = System.IntPtr.Zero;
                oa.SecurityQualityOfService = System.IntPtr.Zero;
                IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
                int status;
                try
                {
                    status = NtCreateFile(out handle, desiredAccess, ref oa, ref iosb,
                        System.IntPtr.Zero, 0, shareAccess, disposition,
                        createOptions | FILE_SYNCHRONOUS_IO_NONALERT, System.IntPtr.Zero, 0);
                }
                finally
                {
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(oa.ObjectName);
                }
                return status;
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.FreeHGlobal(nameBuffer);
            }
        }

        private static FILE_ATTRIBUTE_TAG_INFORMATION QueryAttributesCore(System.IntPtr handle, string path)
        {
            System.IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(
                System.Runtime.InteropServices.Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFORMATION)));
            try
            {
                IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
                int status = NtQueryInformationFile(handle, ref iosb, buffer,
                    (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFORMATION)),
                    FileAttributeTagInformation);
                if (status != 0)
                {
                    ThrowStatus("attribute query on", path, status);
                }
                return (FILE_ATTRIBUTE_TAG_INFORMATION)System.Runtime.InteropServices.Marshal.PtrToStructure(
                    buffer, typeof(FILE_ATTRIBUTE_TAG_INFORMATION));
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);
            }
        }

        private static string QueryFileId(System.IntPtr handle, string path)
        {
            int size = 8 + 16; // VolumeSerialNumber + FILE_ID_128
            System.IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
            try
            {
                IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
                int status = NtQueryInformationFile(handle, ref iosb, buffer, (uint)size, FileIdInformation);
                if (status != 0)
                {
                    ThrowStatus("file id query on", path, status);
                }
                byte[] bytes = new byte[size];
                System.Runtime.InteropServices.Marshal.Copy(buffer, bytes, 0, size);
                return Hex(bytes);
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);
            }
        }

        /// Open every component of an absolute drive path relative to its
        /// pinned parent, refusing any reparse point in the chain. The final
        /// handle carries the requested access (deletion needs DELETE).
        private static System.IntPtr OpenPinnedChain(string fullPath, bool allowMissing, uint finalAccess, out bool missing)
        {
            missing = false;
            string full = System.IO.Path.GetFullPath(fullPath).TrimEnd('\\');
            if (full.Length < 3 || full[1] != ':' || full[2] != '\\')
            {
                throw new NativeRefuseException("NATIVE_PATH", "managed roots must be absolute drive paths: " + fullPath);
            }
            System.IntPtr current = OpenDriveRoot(full.Substring(0, 3));
            string rest = full.Substring(3);
            if (rest.Length == 0)
            {
                throw new NativeRefuseException("NATIVE_PATH", "managed root cannot be a drive root");
            }
            string[] parts = rest.Split('\\');
            System.Collections.Generic.List<System.IntPtr> opened = new System.Collections.Generic.List<System.IntPtr>();
            opened.Add(current);
            try
            {
                for (int i = 0; i < parts.Length; i++)
                {
                    string component = parts[i];
                    if (component.Length == 0) continue;
                    uint access = (i == parts.Length - 1) ? finalAccess : (FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE);
                    System.IntPtr child;
                    int status = OpenRelativeCore(current, component,
                        access,
                        FILE_OPEN,
                        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
                        out child);
                    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND)
                    {
                        if (allowMissing)
                        {
                            foreach (System.IntPtr h in opened) CloseHandle(h);
                            missing = true;
                            return System.IntPtr.Zero;
                        }
                        throw new NativeRefuseException("ZIP_DEST_MISSING", "chain component missing: " + component);
                    }
                    if (status != 0)
                    {
                        ThrowStatus("chain open of", component, status);
                    }
                    string chainPath = full.Substring(0, System.Math.Min(full.Length, 3)) + string.Join("\\", parts, 0, i + 1);
                    FILE_ATTRIBUTE_TAG_INFORMATION attrs = QueryAttributesCore(child, chainPath);
                    if ((attrs.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                    {
                        CloseHandle(child);
                        throw new NativeRefuseException("ZIP_REPARSE_POINT", "pinned chain crosses reparse point: " + chainPath);
                    }
                    opened.Add(child);
                    current = child;
                }
                // transfer ownership of the final handle to caller
                System.IntPtr result = current;
                opened.RemoveAt(opened.Count - 1);
                foreach (System.IntPtr h in opened) CloseHandle(h);
                return result;
            }
            catch
            {
                foreach (System.IntPtr h in opened) CloseHandle(h);
                throw;
            }
        }

        private sealed class DirectoryCache : System.IDisposable
        {
            private readonly System.Collections.Generic.Dictionary<string, System.IntPtr> handles =
                new System.Collections.Generic.Dictionary<string, System.IntPtr>(
                    System.StringComparer.OrdinalIgnoreCase);
            private readonly string rootFullPath;

            public DirectoryCache(System.IntPtr rootHandle, string rootFullPath)
            {
                this.rootFullPath = rootFullPath;
                handles[string.Empty] = rootHandle;
            }

            public System.IntPtr EnsureDirectory(string[] components)
            {
                string prefix = string.Empty;
                System.IntPtr parent = handles[string.Empty];
                for (int i = 0; i < components.Length; i++)
                {
                    string component = components[i];
                    prefix = prefix.Length == 0 ? component : prefix + "\\" + component;
                    System.IntPtr existing;
                    if (handles.TryGetValue(prefix, out existing))
                    {
                        parent = existing;
                        continue;
                    }
                    System.IntPtr child;
                    int status = OpenRelativeCore(parent, component,
                        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                        FILE_OPEN_IF,
                        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
                        out child);
                    if (status == STATUS_OBJECT_NAME_COLLISION)
                    {
                        throw new NativeRefuseException("ZIP_ENTRY_COLLISION", prefix);
                    }
                    if (status != 0)
                    {
                        ThrowStatus("directory create of", prefix, status);
                    }
                    string fullPath = rootFullPath + "\\" + prefix;
                    FILE_ATTRIBUTE_TAG_INFORMATION attrs = QueryAttributesCore(child, fullPath);
                    if ((attrs.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                    {
                        CloseHandle(child);
                        throw new NativeRefuseException("ZIP_REPARSE_POINT", fullPath);
                    }
                    handles[prefix] = child;
                    parent = child;
                }
                return parent;
            }

            public void Dispose()
            {
                foreach (System.Collections.Generic.KeyValuePair<string, System.IntPtr> pair in handles)
                {
                    CloseHandle(pair.Value);
                }
                handles.Clear();
            }
        }

        // ------------------------------------------------------------------
        // entry-name validation
        // ------------------------------------------------------------------

        private static readonly string[] ReservedNames = new string[]
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        };

        private static string[] EntryComponents(string entryName, string destFull, string destPrefix)
        {
            if (entryName.IndexOf(':') >= 0)
            {
                throw new NativeRefuseException("ZIP_ALTERNATE_STREAM", entryName);
            }
            // Win32 path normalization silently strips trailing dots/spaces,
            // so the raw (pre-GetFullPath) segments must be checked first or a
            // "trailing." entry would extract under a silently renamed target.
            string[] rawSegments = entryName.Replace('/', '\\').Split('\\');
            for (int i = 0; i < rawSegments.Length; i++)
            {
                string seg = rawSegments[i];
                if (seg.Length == 0 || seg == "." || seg == "..") continue;
                char last = seg[seg.Length - 1];
                if (last == '.' || last == ' ')
                {
                    throw new NativeRefuseException("ZIP_NAME_INVALID", seg);
                }
            }
            string target;
            try
            {
                target = System.IO.Path.GetFullPath(System.IO.Path.Combine(destFull, entryName));
            }
            catch (System.Exception)
            {
                throw new NativeRefuseException("ZIP_PATH_ESCAPE", entryName);
            }
            if (!target.StartsWith(destPrefix, System.StringComparison.OrdinalIgnoreCase) && target != destFull)
            {
                throw new NativeRefuseException("ZIP_PATH_ESCAPE", entryName);
            }
            string rel = target.Length > destFull.Length
                ? target.Substring(destPrefix.Length)
                : string.Empty;
            string[] raw = rel.Split('\\');
            System.Collections.Generic.List<string> parts = new System.Collections.Generic.List<string>();
            for (int i = 0; i < raw.Length; i++)
            {
                if (raw[i].Length == 0) continue;
                string component = raw[i];
                if (component == "." || component == "..")
                {
                    throw new NativeRefuseException("ZIP_PATH_ESCAPE", entryName);
                }
                if (component[component.Length - 1] == '.' || component[component.Length - 1] == ' ')
                {
                    throw new NativeRefuseException("ZIP_NAME_INVALID", component);
                }
                for (int c = 0; c < component.Length; c++)
                {
                    char ch = component[c];
                    if (ch < 0x20 || ch == '"' || ch == '<' || ch == '>' || ch == '|' || ch == '*' || ch == '?')
                    {
                        throw new NativeRefuseException("ZIP_NAME_INVALID", component);
                    }
                }
                string upper = component.ToUpperInvariant();
                string stem = upper;
                int dot = upper.IndexOf('.');
                if (dot >= 0) stem = upper.Substring(0, dot);
                for (int r = 0; r < ReservedNames.Length; r++)
                {
                    if (stem == ReservedNames[r])
                    {
                        throw new NativeRefuseException("ZIP_NAME_INVALID", component);
                    }
                }
                parts.Add(component);
            }
            return parts.ToArray();
        }

        // ------------------------------------------------------------------
        // Extract
        // ------------------------------------------------------------------

        public static string Extract(string archivePath, string destination, string expectedSha256Lower)
        {
            string destFull = System.IO.Path.GetFullPath(destination).TrimEnd('\\');
            string destPrefix = destFull + "\\";
            using (System.IO.FileStream stream = new System.IO.FileStream(
                archivePath, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.None))
            {
                if (stream.Length > MaxArchiveBytes) throw new NativeRefuseException("ZIP_ARCHIVE_LIMIT");
                string actualSha256;
                using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
                {
                    byte[] buffer = new byte[65536];
                    int n;
                    while ((n = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        sha.TransformBlock(buffer, 0, n, buffer, 0);
                    }
                    actualSha256 = ShaFinal(sha);
                }
                if (actualSha256 != expectedSha256Lower.ToLowerInvariant())
                {
                    throw new NativeRefuseException("ZIP_SHA_MISMATCH");
                }
                stream.Position = 0;
                using (System.IO.Compression.ZipArchive zip =
                    new System.IO.Compression.ZipArchive(stream, System.IO.Compression.ZipArchiveMode.Read, false))
                {
                    if (zip.Entries.Count > MaxEntries) throw new NativeRefuseException("ZIP_ENTRY_LIMIT");
                    long declaredTotal = 0;
                    foreach (System.IO.Compression.ZipArchiveEntry entry in zip.Entries)
                    {
                        if (entry.Length > MaxEntryBytes) throw new NativeRefuseException("ZIP_EXPANDED_LIMIT");
                        declaredTotal += entry.Length;
                        if (declaredTotal > MaxExpandedBytes) throw new NativeRefuseException("ZIP_EXPANDED_LIMIT");
                        if (entry.Length > 0 &&
                            (entry.CompressedLength == 0 ||
                             ((double)entry.Length / (double)System.Math.Max(1.0, (double)entry.CompressedLength)) > MaxRatio))
                        {
                            throw new NativeRefuseException("ZIP_COMPRESSION_RATIO_LIMIT");
                        }
                        EntryComponents(entry.FullName, destFull, destPrefix);
                    }

                    System.Text.StringBuilder output = new System.Text.StringBuilder();
                    long writtenTotal = 0;
                    bool missing;
                    System.IntPtr rootHandle = OpenPinnedChain(destFull, false, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, out missing);
                    using (DirectoryCache cache = new DirectoryCache(rootHandle, destFull))
                    {
                        foreach (System.IO.Compression.ZipArchiveEntry entry in zip.Entries)
                        {
                            string[] parts = EntryComponents(entry.FullName, destFull, destPrefix);
                            if (System.String.IsNullOrEmpty(entry.Name))
                            {
                                cache.EnsureDirectory(parts);
                                output.Append(System.IO.Path.GetFullPath(
                                    System.IO.Path.Combine(destFull, entry.FullName)).TrimEnd('\\'));
                                output.Append('\t').Append('-').Append('\t').Append('0').Append('\n');
                                continue;
                            }
                            string fileName = parts[parts.Length - 1];
                            string[] dirParts = new string[parts.Length - 1];
                            System.Array.Copy(parts, dirParts, dirParts.Length);
                            System.IntPtr parent = cache.EnsureDirectory(dirParts);

                            System.IntPtr fileHandle;
                            int status = OpenRelativeCore(parent, fileName,
                                FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                FILE_CREATE,
                                FILE_NON_DIRECTORY_FILE,
                                out fileHandle);
                            if (status == STATUS_OBJECT_NAME_COLLISION)
                            {
                                throw new NativeRefuseException("ZIP_ENTRY_COLLISION", entry.FullName);
                            }
                            if (status != 0)
                            {
                                ThrowStatus("create-new of", entry.FullName, status);
                            }
                            string target = System.IO.Path.GetFullPath(System.IO.Path.Combine(destFull, entry.FullName));
                            try
                            {
                                FILE_ATTRIBUTE_TAG_INFORMATION attrs = QueryAttributesCore(fileHandle, target);
                                if ((attrs.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                                {
                                    throw new NativeRefuseException("ZIP_REPARSE_POINT", target);
                                }
                                if ((attrs.FileAttributes & 0x10) != 0) // FILE_ATTRIBUTE_DIRECTORY
                                {
                                    throw new NativeRefuseException("ZIP_ENTRY_COLLISION", target);
                                }
                                long entryWritten = 0;
                                using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
                                {
                                    using (System.IO.Stream input = entry.Open())
                                    {
                                        byte[] buffer = new byte[65536];
                                        int n;
                                        IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
                                        while ((n = input.Read(buffer, 0, buffer.Length)) > 0)
                                        {
                                            entryWritten += n;
                                            writtenTotal += n;
                                            if (entryWritten > MaxEntryBytes || writtenTotal > MaxExpandedBytes)
                                            {
                                                throw new NativeRefuseException("ZIP_RUNTIME_EXPANDED_LIMIT");
                                            }
                                            int writeStatus = NtWriteFile(fileHandle, System.IntPtr.Zero,
                                                System.IntPtr.Zero, System.IntPtr.Zero, ref iosb, buffer, (uint)n,
                                                System.IntPtr.Zero, System.IntPtr.Zero);
                                            if (writeStatus != 0)
                                            {
                                                ThrowStatus("write to", target, writeStatus);
                                            }
                                            sha.TransformBlock(buffer, 0, n, buffer, 0);
                                        }
                                    }
                                    string fileSha = ShaFinal(sha);
                                    if (entryWritten != entry.Length)
                                    {
                                        throw new NativeRefuseException("ZIP_LENGTH_MISMATCH", entry.FullName);
                                    }
                                    output.Append(target).Append('\t').Append(fileSha).Append('\t')
                                        .Append(entryWritten).Append('\n');
                                }
                            }
                            finally
                            {
                                CloseHandle(fileHandle);
                            }
                        }
                    }
                    return output.ToString();
                }
            }
        }

        // ------------------------------------------------------------------
        // RemoveTree
        // ------------------------------------------------------------------

        private sealed class CensusObject
        {
            public string RelativePath;
            public string FullPath;
            public bool IsDirectory;
            public string FileId;
            public string Sha256;
            public System.IntPtr Handle;
        }

        private sealed class InstallIdentity
        {
            public string Kind;
            public string FileId;
            public string Sha256;
        }

        private static System.Collections.Generic.HashSet<string> ParseManifest(string manifestText)
        {
            System.Collections.Generic.HashSet<string> manifest =
                new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
            string[] manifestLines = manifestText.Split('\n');
            for (int i = 0; i < manifestLines.Length; i++)
            {
                string line = manifestLines[i].Trim();
                if (line.Length == 0) continue;
                manifest.Add(System.IO.Path.GetFullPath(line).TrimEnd('\\'));
            }
            return manifest;
        }

        public static string SnapshotTree(string rootPath, string manifestText)
        {
            System.Collections.Generic.HashSet<string> manifest = ParseManifest(manifestText);
            string rootFull = System.IO.Path.GetFullPath(rootPath).TrimEnd('\\');
            if (!manifest.Contains(rootFull))
            {
                throw new NativeRefuseException("IDENTITY_SCOPE", "snapshot manifest omits root " + rootFull);
            }

            bool missing;
            System.IntPtr rootHandle = OpenPinnedChain(
                rootPath, false, FILE_READ_DATA | FILE_READ_ATTRIBUTES | DELETE_ACCESS | SYNCHRONIZE, out missing);
            System.Collections.Generic.List<CensusObject> census =
                new System.Collections.Generic.List<CensusObject>();
            System.Collections.Generic.List<System.IntPtr> toClose =
                new System.Collections.Generic.List<System.IntPtr>();
            toClose.Add(rootHandle);
            try
            {
                WalkCensus(rootHandle, rootFull, "", census, toClose);
                if (manifest.Count != census.Count + 1)
                {
                    throw new NativeRefuseException(
                        "FOREIGN_CONTENT",
                        "snapshot manifest/object count differs for " + rootFull);
                }
                for (int i = 0; i < census.Count; i++)
                {
                    if (!manifest.Contains(census[i].FullPath))
                    {
                        throw new NativeRefuseException("FOREIGN_CONTENT", census[i].FullPath);
                    }
                }

                System.Text.StringBuilder output = new System.Text.StringBuilder();
                output.Append(rootFull).Append('\t').Append("dir").Append('\t')
                    .Append(QueryFileId(rootHandle, rootFull)).Append('\t').Append('-').Append('\n');
                census.Sort(delegate (CensusObject a, CensusObject b)
                {
                    return string.CompareOrdinal(a.FullPath, b.FullPath);
                });
                for (int i = 0; i < census.Count; i++)
                {
                    CensusObject obj = census[i];
                    output.Append(obj.FullPath).Append('\t')
                        .Append(obj.IsDirectory ? "dir" : "file").Append('\t')
                        .Append(obj.FileId).Append('\t')
                        .Append(obj.IsDirectory ? "-" : obj.Sha256).Append('\n');
                }
                return output.ToString();
            }
            finally
            {
                foreach (System.IntPtr h in toClose)
                {
                    if (h != System.IntPtr.Zero) CloseHandle(h);
                }
                for (int i = 0; i < census.Count; i++)
                {
                    if (census[i].Handle != System.IntPtr.Zero) CloseHandle(census[i].Handle);
                }
            }
        }

        public static string RemoveTree(string rootPath, string manifestText, string identityText)
        {
            System.Collections.Generic.HashSet<string> manifest = ParseManifest(manifestText);
            System.Collections.Generic.Dictionary<string, InstallIdentity> identities =
                new System.Collections.Generic.Dictionary<string, InstallIdentity>(
                    System.StringComparer.OrdinalIgnoreCase);
            if (identityText != null && identityText.Length > 0)
            {
                string[] identityLines = identityText.Split('\n');
                for (int i = 0; i < identityLines.Length; i++)
                {
                    string line = identityLines[i].Trim();
                    if (line.Length == 0) continue;
                    string[] fields = line.Split('\t');
                    if (fields.Length != 4)
                    {
                        throw new NativeRefuseException("IDENTITY_MALFORMED", line);
                    }
                    string path = System.IO.Path.GetFullPath(fields[0]).TrimEnd('\\');
                    string kind = fields[1];
                    string fileId = fields[2].ToLowerInvariant();
                    string sha = fields[3].ToLowerInvariant();
                    if (!manifest.Contains(path))
                    {
                        throw new NativeRefuseException("IDENTITY_SCOPE", path);
                    }
                    if ((kind != "file" && kind != "dir") || !IsLowerHex(fileId, 48))
                    {
                        throw new NativeRefuseException("IDENTITY_MALFORMED", path);
                    }
                    if ((kind == "file" && !IsLowerHex(sha, 64)) || (kind == "dir" && sha != "-"))
                    {
                        throw new NativeRefuseException("IDENTITY_MALFORMED", path);
                    }
                    InstallIdentity identity = new InstallIdentity();
                    identity.Kind = kind;
                    identity.FileId = fileId;
                    identity.Sha256 = sha;
                    if (identities.ContainsKey(path))
                    {
                        throw new NativeRefuseException("IDENTITY_MALFORMED", "duplicate " + path);
                    }
                    identities.Add(path, identity);
                }
            }

            string rootFull = System.IO.Path.GetFullPath(rootPath).TrimEnd('\\');
            bool missing;
            System.IntPtr rootHandle = OpenPinnedChain(
                rootPath, true, FILE_READ_DATA | FILE_READ_ATTRIBUTES | DELETE_ACCESS | SYNCHRONIZE, out missing);
            if (missing)
            {
                return "ABSENT\n";
            }

            System.Collections.Generic.List<CensusObject> census = new System.Collections.Generic.List<CensusObject>();
            System.Collections.Generic.List<System.IntPtr> toClose = new System.Collections.Generic.List<System.IntPtr>();
            toClose.Add(rootHandle);
            try
            {
                WalkCensus(rootHandle, rootFull, "", census, toClose);

                // membership + install-time object identity: every surviving object
                // must be the same NT object (and, for files, the same bytes)
                // that the install snapshot recorded.
                InstallIdentity rootIdentity;
                if (!identities.TryGetValue(rootFull, out rootIdentity))
                {
                    throw new NativeRefuseException("IDENTITY_MISSING", "no install-time identity for " + rootFull);
                }
                string rootFileId = QueryFileId(rootHandle, rootFull);
                if (rootIdentity.Kind != "dir" || rootIdentity.FileId != rootFileId)
                {
                    throw new NativeRefuseException("FOREIGN_CONTENT", "root identity replacement detected at " + rootFull);
                }
                if (identities.Count != manifest.Count)
                {
                    throw new NativeRefuseException("IDENTITY_MISSING", "identity set is not complete for manifest");
                }

                for (int i = 0; i < census.Count; i++)
                {
                    CensusObject obj = census[i];
                    if (!manifest.Contains(obj.FullPath))
                    {
                        throw new NativeRefuseException("FOREIGN_CONTENT", obj.FullPath);
                    }
                    InstallIdentity identity;
                    if (!identities.TryGetValue(obj.FullPath, out identity))
                    {
                        throw new NativeRefuseException("IDENTITY_MISSING", "no install-time identity for " + obj.FullPath);
                    }
                    string actualKind = obj.IsDirectory ? "dir" : "file";
                    if (identity.Kind != actualKind || identity.FileId != obj.FileId)
                    {
                        throw new NativeRefuseException(
                            "FOREIGN_CONTENT", "same-path object replacement detected at " + obj.FullPath);
                    }
                    if (!obj.IsDirectory && identity.Sha256 != obj.Sha256)
                    {
                        throw new NativeRefuseException(
                            "FOREIGN_CONTENT", "same-path content replacement detected at " + obj.FullPath);
                    }
                }

                // deepest-first delete BY HANDLE with POSIX semantics
                census.Sort(delegate (CensusObject a, CensusObject b)
                {
                    int da = Depth(a.RelativePath);
                    int db = Depth(b.RelativePath);
                    if (da != db) return db - da;
                    return string.CompareOrdinal(a.RelativePath, b.RelativePath);
                });

                System.Collections.Generic.List<string> removed = new System.Collections.Generic.List<string>();
                System.Collections.Generic.List<string> retained = new System.Collections.Generic.List<string>();
                bool stopped = false;
                for (int i = 0; i < census.Count; i++)
                {
                    CensusObject obj = census[i];
                    if (stopped)
                    {
                        retained.Add(obj.FullPath);
                        continue;
                    }
                    string currentId = QueryFileId(obj.Handle, obj.FullPath);
                    if (currentId != obj.FileId)
                    {
                        throw new NativeRefuseException("FOREIGN_CONTENT",
                            "identity swap detected at " + obj.FullPath);
                    }
                    FILE_DISPOSITION_INFORMATION_EX disposition = new FILE_DISPOSITION_INFORMATION_EX();
                    disposition.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
                    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
                    int status = NtSetInformationFile(obj.Handle, ref iosb, ref disposition,
                        (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(FILE_DISPOSITION_INFORMATION_EX)),
                        FileDispositionInformationEx);
                    if (status != 0)
                    {
                        retained.Add(obj.FullPath + " NTSTATUS=0x" + status.ToString("X8"));
                        stopped = true; // e.g. directory gained foreign content after census
                        continue;
                    }
                    removed.Add(obj.FullPath);
                    // Close the disposed object's handle so the unlink takes
                    // effect immediately (classic disposition defers the name
                    // removal to the last handle close; the census kept every
                    // handle open). Deletion remains pinned to THIS handle.
                    CloseHandle(obj.Handle);
                    obj.Handle = System.IntPtr.Zero;
                }
                if (!stopped)
                {
                    FILE_DISPOSITION_INFORMATION_EX disposition = new FILE_DISPOSITION_INFORMATION_EX();
                    disposition.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
                    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
                    int status = NtSetInformationFile(rootHandle, ref iosb, ref disposition,
                        (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(FILE_DISPOSITION_INFORMATION_EX)),
                        FileDispositionInformationEx);
                    if (status != 0)
                    {
                        retained.Add(rootFull + " NTSTATUS=0x" + status.ToString("X8"));
                    }
                    else
                    {
                        removed.Add(rootFull);
                        CloseHandle(rootHandle);
                        rootHandle = System.IntPtr.Zero;
                        toClose[0] = System.IntPtr.Zero;
                    }
                }
                if (retained.Count > 0)
                {
                    return "RETAINED\t" + string.Join("|", retained.ToArray()) + "\n" +
                        "REMOVED\t" + string.Join("|", removed.ToArray()) + "\n";
                }
                return "OK\t" + removed.Count.ToString() + "\n" +
                    "REMOVED\t" + string.Join("|", removed.ToArray()) + "\n";
            }
            finally
            {
                foreach (System.IntPtr h in toClose)
                {
                    if (h != System.IntPtr.Zero) CloseHandle(h);
                }
                for (int i = 0; i < census.Count; i++)
                {
                    if (census[i].Handle != System.IntPtr.Zero) CloseHandle(census[i].Handle);
                }
            }
        }

        private static int Depth(string relativePath)
        {
            if (relativePath.Length == 0) return 0;
            return relativePath.Split('\\').Length;
        }

        private static void WalkCensus(
            System.IntPtr dirHandle,
            string rootFull,
            string relative,
            System.Collections.Generic.List<CensusObject> census,
            System.Collections.Generic.List<System.IntPtr> toClose)
        {
            uint bufferSize = 65536;
            System.IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal((int)bufferSize);
            try
            {
                bool restart = true;
                while (true)
                {
                    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
                    int status = NtQueryDirectoryFile(dirHandle, System.IntPtr.Zero, System.IntPtr.Zero,
                        System.IntPtr.Zero, ref iosb, buffer, bufferSize, FileDirectoryInformation,
                        false, System.IntPtr.Zero, restart);
                    restart = false;
                    if (status == STATUS_NO_MORE_FILES) break;
                    if (status != 0)
                    {
                        ThrowStatus("enumeration of", rootFull + "\\" + relative, status);
                    }
                    long offset = 0;
                    while (true)
                    {
                        System.IntPtr entry = new System.IntPtr(buffer.ToInt64() + offset);
                        int next = System.Runtime.InteropServices.Marshal.ReadInt32(entry, 0);
                        long endOfFile = System.Runtime.InteropServices.Marshal.ReadInt64(entry, 40);
                        uint attributes = (uint)System.Runtime.InteropServices.Marshal.ReadInt32(entry, 56);
                        int nameLength = System.Runtime.InteropServices.Marshal.ReadInt32(entry, 60);
                        string name = System.Runtime.InteropServices.Marshal.PtrToStringUni(
                            new System.IntPtr(entry.ToInt64() + 64), nameLength / 2);
                        if (name != "." && name != "..")
                        {
                            string childRelative = relative.Length == 0 ? name : relative + "\\" + name;
                            string childFull = rootFull + "\\" + childRelative;
                            System.IntPtr child;
                            int openStatus = OpenRelativeCoreShared(dirHandle, name,
                                DELETE_ACCESS | FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                FILE_OPEN,
                                FILE_OPEN_REPARSE_POINT,
                                FILE_SHARE_READ,
                                out child);
                            if (openStatus != 0)
                            {
                                ThrowStatus("census open of", childFull, openStatus);
                            }
                            FILE_ATTRIBUTE_TAG_INFORMATION attrs = QueryAttributesCore(child, childFull);
                            if ((attrs.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                            {
                                CloseHandle(child);
                                throw new NativeRefuseException("FOREIGN_REPARSE", childFull);
                            }
                            CensusObject obj = new CensusObject();
                            obj.RelativePath = childRelative;
                            obj.FullPath = childFull;
                            obj.IsDirectory = (attributes & 0x10) != 0;
                            obj.Handle = child;
                            obj.FileId = QueryFileId(child, childFull);
                            if (!obj.IsDirectory)
                            {
                                obj.Sha256 = HashByHandle(child, childFull, endOfFile);
                            }
                            census.Add(obj);
                            if (obj.IsDirectory)
                            {
                                WalkCensus(child, rootFull, childRelative, census, toClose);
                            }
                        }
                        if (next == 0) break;
                        offset += next;
                    }
                }
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);
            }
        }

        private static string HashByHandle(System.IntPtr handle, string path, long length)
        {
            // ReadFile over the SAME no-follow pinned handle via a
            // non-owning SafeFileHandle wrapper: identity pinning is the
            // handle, not the syscall flavor.
            Microsoft.Win32.SafeHandles.SafeFileHandle safe =
                new Microsoft.Win32.SafeHandles.SafeFileHandle(handle, false);
            using (safe)
            {
                using (System.IO.FileStream stream = new System.IO.FileStream(
                    safe, System.IO.FileAccess.Read, 65536))
                {
                    byte[] hash;
                    using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
                    {
                        hash = sha.ComputeHash(stream);
                    }
                    return Hex(hash);
                }
            }
        }
    }
}
