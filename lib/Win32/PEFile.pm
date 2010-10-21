package Win32::PEFile;
use strict;
use warnings;
use Encode;
use Carp;

our $VERSION = '0.7001';

#-- Constant data

my %rsrcTypes = (
    1  => 'CURSOR',
    2  => 'BITMAP',
    3  => 'ICON',
    4  => 'MENU',
    5  => 'DIALOG',
    6  => 'STRING',
    7  => 'FONTDIR',
    8  => 'FONT',
    9  => 'ACCELERATOR',
    10 => 'RCDATA',
    11 => 'MESSAGETABLE',
    12 => 'GROUP_CURSOR',
    13 => 'GROUP_ICON',
    16 => 'VERSION',
    17 => 'DLGINCLUDE',
    19 => 'PLUGPLAY',
    20 => 'VXD',
    21 => 'ANICURSOR',
    22 => 'ANIICON',
    23 => 'HTML',
    24 => 'MANIFEST',
);

#-- Members

sub new {
    my ($class, %params) = @_;
    my $self = bless \%params, $class;

    die "Parameter -file is required for $class->new ()\n"
        if !exists $params{'-file'};
    $self->{ok} = eval {$self->_parseFile ()};
    $self->{err} = $@ || '';
    return $self;
}


sub isOk {
    my ($self) = @_;
    return $self->{ok};
}


sub lastError {
    my ($self) = @_;
    return $self->{err};
}


sub _parseFile {
    my ($self) = @_;
    my $buffer = '';

    eval {
        open my $peFile, '<:raw', $self->{'-file'}
            or die "unable to open file - $!\n";

        read $peFile, $buffer, 256, 0 or die "file read error: $!\n";

        die "No MZ header found\n" if $buffer !~ /^MZ/;

        my $peOffset = substr ($buffer, 0x3c, 4);
        $peOffset = unpack ('V', $peOffset);
        seek $peFile, $peOffset, 0;

        (read $peFile, $buffer, 4 and $buffer =~ /^PE\0\0/)
            or die "corrupt or not a PE file \n";

        read $peFile, $buffer, 20, 0 or die "file read error: $!\n";
        @{$self->{COFF}}{
            qw(
                Machine NumberOfSections TimeDateStamp PointerToSymbolTable
                NumberOfSymbols SizeOfOptionalHeader Characteristics
                )
            }
            = unpack ('vvVVVvv', $buffer);

        if ($self->{COFF}{SizeOfOptionalHeader}) {
            my $opt = $self->{OptionalHeader} = {};
            my @ohFields = qw (
                Magic MajorLinkerVersion MinorLinkerVersion SizeOfCode
                SizeOfInitializedData SizeOfUninitializedData
                AddressOfEntryPoint BaseOfCode
                );

            read $peFile, $opt->{raw}, $self->{COFF}{SizeOfOptionalHeader}, 0;
            @{$opt}{@ohFields} = unpack ('vCCVVVVV', $opt->{raw});

            my $blk = substr $opt->{raw}, 24;
            if ($opt->{Magic} == 0x20B) {
                $self->_parsePE32PlusOpt ($blk);
            } else {
                $self->_parsePE32Opt ($blk);
            }

            $self->_parseSectionsTable ($peFile);
            $self->_findDataDirData    ($peFile);
        }

        close $peFile;
    };

    die "Error in PE file $self->{'-file'}: $@\n" if $@;
    return 1;
}


sub _parsePE32Opt {
    my ($self, $blk) = @_;
    my $len    = length $blk;
    my @fields = (
        qw(
            ImageBase SectionAlignment FileAlignment MajorOperatingSystemVersion
            MinorOperatingSystemVersion MajorImageVersion MinorImageVersion
            MajorSubsystemVersion MinorSubsystemVersion Win32VersionValue
            SizeOfImage SizeOfHeaders CheckSum Subsystem DllCharacteristics
            SizeOfStackReserve SizeOfStackCommit SizeOfHeapReserve
            SizeOfHeapCommit LoaderFlags NumberOfRvaAndSizes )
    );

    $self->{OptionalHeader}{BaseOfData} = unpack ('V', substr $blk, 0, 4, '');
    @{$self->{OptionalHeader}}{@fields} =
        unpack ('VVVvvvvvvVVVVvvVVVVVV', $blk);

    # $blk passed in starts at offset 20 and 4 bytes are removed by substr above
    # so offset to data directory is 96 - (24 + 4) = 68
    $self->_parseDataDirectory (substr $blk, 68);
}


sub _parsePE32PlusOpt {
    my ($self, $blk) = @_;
    my $len    = length $blk;
    my @fields = (
        qw(
            ImageBaseL ImageBaseH SectionAlignment FileAlignment
            MajorOperatingSystemVersion MinorOperatingSystemVersion
            MajorImageVersion MinorImageVersion MajorSubsystemVersion
            MinorSubsystemVersion Win32VersionValue SizeOfImage SizeOfHeaders
            CheckSum Subsystem DllCharacteristics SizeOfStackReserveL
            SizeOfStackReserveH SizeOfStackCommitL SizeOfStackCommitH
            SizeOfHeapReserveL SizeOfHeapReserveH SizeOfHeapCommitL
            SizeOfHeapCommitH LoaderFlags NumberOfRvaAndSizes )
    );

    @{$self->{OptionalHeader}}{@fields} =
        unpack ('VVVVvvvvvvVVVVvvVVVVVVVVVV', $blk);

    # $blk passed in starts at offset 20 so offset to data directory is 112 - 24
    $self->_parseDataDirectory (substr $blk, 88);
}


sub _parseDataDirectory {
    my ($self, $blk) = @_;
    my $len    = length $blk;
    my @fields = qw(.edata .idata .rsrc .pdata certTable .reloc .debug
        Architecture GlobalPtr .tls LoadConfig BoundImport IAT
        DelayImportDescriptor .cormeta Reserved
        );
    my @entries;

    for (1 .. $self->{OptionalHeader}{NumberOfRvaAndSizes}) {
        my $addr = unpack ('V', substr $blk, 0, 4, '');
        my $size = unpack ('V', substr $blk, 0, 4, '');

        push @entries, {imageRVA => $addr, size => $size};
        last if !length $blk;
    }

    @{$self->{COFF}{'!DataDir'}}{@fields} = @entries;
    return;
}


sub _parseSectionsTable {
    my ($self, $peFile) = @_;

    my $sections = $self->{sections} = {};
    my @secFields = (
        qw(
            Name VirtualSize VirtualAddress SizeOfRawData PointerToRawData
            PointerToRelocations PointerToLinenumbers NumberOfRelocations
            NumberOfLinenumbers Characteristics
            )
    );

    for (1 .. $self->{COFF}{NumberOfSections}) {
        my %section;
        my $raw;

        read $peFile, $raw, 40, 0;
        @section{@secFields} = unpack ('a8VVVVVVvvV', $raw);
        $section{Name} =~ s/\x00+$//;
        $sections->{$section{Name}} = \%section;
    }
}


sub _findDataDirData {
    my ($self, $peFile) = @_;

    for my $entry (values %{$self->{COFF}{'!DataDir'}}) {
        next if !$entry->{size};    # size is zero

        for my $sectionName (keys %{$self->{sections}}) {
            my $section = $self->{sections}{$sectionName};
            my $fileBias =
                $section->{VirtualAddress} - $section->{PointerToRawData};

            next if $section->{VirtualAddress} > $entry->{imageRVA};
            next
                if $section->{VirtualAddress} + $section->{VirtualSize} <
                    $entry->{imageRVA};

            $entry->{fileBias} = $fileBias;
            $entry->{filePos}  = $entry->{imageRVA} - $fileBias;
            last;
        }
    }
}


sub _readSzStr {
    my ($fh, $offset) = @_;
    my $oldPos = tell $fh;
    my $str    = '';

    seek $fh, $offset, 0 if defined $offset;
    read $fh, my $strBytes, 2 or die "file read error: $!\n";
    $strBytes = 2 * unpack ('v', $strBytes);

    if ($strBytes) {
        read $fh, $str, $strBytes or die "file read error: $!\n";
        $str = Encode::decode ('UTF-16LE', $str);
    }

    seek $fh, $oldPos, 0 if defined $offset;
    return $str;
}


sub getEntryPoint {
    my ($self, $routineName) = @_;

    return if !exists $self->{COFF}{'!DataDir'}{'.edata'};
    return exists $self->{Exports}{$routineName}
        if exists $self->{Exports};

    my $edataHdr = $self->{COFF}{'!DataDir'}{'.edata'};

    open my $peFile, '<:raw', $self->{'-file'}
        or die "unable to open file - $!\n";
    seek $peFile, $edataHdr->{filePos}, 0;
    read $peFile, (my $eData), $edataHdr->{size};

    my %dirTable;

    @dirTable{
        qw(
            Flags Timestamp VerMaj VerMin NameRVA Base ATEntries Names
            ExportTabRVA NameTabRVA OrdTabRVA
            )
        }
        = unpack ('VVvvVVVVVVV', $eData);

    my $nameTableFileAddr = $dirTable{NameTabRVA} - $edataHdr->{fileBias};

    seek $peFile, $nameTableFileAddr, 0;
    read $peFile, (my $nameData), $dirTable{Names} * 4;

    for my $index (0 .. $dirTable{Names} - 1) {
        my $addr = unpack ('V', substr $nameData, $index * 4, 4);

        next if !$addr;
        seek $peFile, $addr - $edataHdr->{fileBias}, 0;

        my $nameStr = '';
        my $strEnd;

        read $peFile, $nameStr, 256, length $nameStr
            while ($strEnd = index $nameStr, "\0") < 0;

        my $epName = substr $nameStr, 0, $strEnd;

        $self->{Exports}{$epName} = $index;
    }

    close $peFile;
    return exists $self->{Exports}{$routineName};
}


sub getVersionStrings {
    my ($self, $lang) = @_;

    $lang = $self->_parseVersionInfo ($lang);

    return $self->{rsrc}{VERSION}{1}{$lang}{StringFileInfo};
}


sub getFixedVersionValues {
    my ($self, $lang) = @_;

    $lang = $self->_parseVersionInfo ($lang);

    return $self->{rsrc}{VERSION}{1}{$lang}{FixedFileInfo};
}


sub _parseVersionInfo {
    my ($self, $lang) = @_;

    return if !exists $self->{COFF}{'!DataDir'}{'.rsrc'};
    return $lang if defined $lang && exists $self->{rsrc}{VERSION}{1}{$lang};

    if (! $self->{rsrc}{VERSION}{1}) {
        my $rsrcHdr = $self->{COFF}{'!DataDir'}{'.rsrc'};

        open my $peFile, '<:raw', $self->{'-file'}
            or die "unable to open file - $!\n";

        $self->{rsrc} = {};
        $self->_parseRsrcTable ($self->{rsrc}, $peFile, 0, $rsrcHdr->{filePos});
        close $peFile;
        return if !exists $self->{rsrc}{VERSION}{1};
    }

    #struct VS_VERSIONINFO {
    #  WORD  wLength;
    #  WORD  wValueLength;
    #  WORD  wType;
    #  WCHAR szKey[]; // "VS_VERSION_INFO".
    #  WORD  Padding1[];
    #  VS_FIXEDFILEINFO Value;
    #  WORD  Padding2[];
    #  WORD  Children[];
    #};

    my %langs = map {$_ => 1} keys %{$self->{rsrc}{VERSION}{1}};

    $lang ||= 0x0409;    # Default to US English
    $lang = (keys %langs)[0] if !exists $langs{$lang};
    return $lang if exists $self->{rsrc}{VERSION}{1}{$lang}{FixedFileInfo};

    my $rsrcEntry = $self->{rsrc}{VERSION}{1}{$lang};
    open my $resIn, '<', \$rsrcEntry->{rsrcData};

    while (read $resIn, (my $data), 6) {
        my %header = (rsrcOffset => $rsrcEntry->{rsrcOffset});

        @header{qw(length valueLength isText)} = unpack ('vvv', $data);
        read $resIn, $header{type}, 4;
        $header{type} = Encode::decode ('UTF-16LE', $header{type});

        if ($header{type} eq 'VS') {
            $self->_parseFixedFileInfo ($rsrcEntry, $resIn, \%header);
        } elsif ($header{type} eq 'Va') {
            $self->_parseVarFileInfo ($rsrcEntry, $resIn, \%header);
        } elsif ($header{type} eq 'St') {
            $self->_parseStringFileInfo ($rsrcEntry, $resIn, \%header);
        } else {
            die "Unknown version resource info prefix: $header{type}\n";
        }
    }

    close $resIn;
    return $lang;
}


sub _parseFixedFileInfo {
    my ($self, $rsrcEntry, $resIn, $header) = @_;

    read $resIn, (my $key), 26;    # remainder of key
    read $resIn, (my $data), 4;    # null terminator and padding
    $header->{type} = $header->{type} . Encode::decode ('UTF-16LE', $key);

    #struct VS_FIXEDFILEINFO {
    #  DWORD dwSignature;
    #  DWORD dwStrucVersion;
    #  DWORD dwFileVersionMS;
    #  DWORD dwFileVersionLS;
    #  DWORD dwProductVersionMS;
    #  DWORD dwProductVersionLS;
    #  DWORD dwFileFlagsMask;
    #  DWORD dwFileFlags;
    #  DWORD dwFileOS;
    #  DWORD dwFileType;
    #  DWORD dwFileSubtype;
    #  DWORD dwFileDateMS;
    #  DWORD dwFileDateLS;
    #};
    my %fixedFileInfo;

    read $resIn, $data, 52;
    @fixedFileInfo{
        qw(
            dwSignature dwStrucVersion dwFileVersionMS dwFileVersionLS
            dwProductVersionMS dwProductVersionLS dwFileFlagsMask dwFileFlags
            dwFileOS dwFileType dwFileSubtype dwFileDateMS dwFileDateLS
            )
        }
        = unpack ('V13', $data);
    seek $resIn, (tell $resIn) % 4, 1; # Skip padding bytes

    $rsrcEntry->{FixedFileInfo} = \%fixedFileInfo;
}


sub _parseStringFileInfo {
    my ($self, $rsrcEntry, $resIn, $header) = @_;

    read $resIn, (my $key), 24;    # remainder of key
    $header->{type} = $header->{type} . Encode::decode ('UTF-16LE', $key);

    my %stringFileInfo;

    #struct StringFileInfo {
    #  WORD        wLength;
    #  WORD        wValueLength;
    #  WORD        wType;
    #  WCHAR       szKey[]; // "StringFileInfo"
    #  WORD        Padding[];
    #  StringTable Children[];
    #};

    my $padding = (tell $resIn) % 4;
    seek $resIn, $padding, 1; # Skip padding bytes following key

    # Read the entire string file info record
    my $pos = tell $resIn;
    read $resIn, (my $strTables), $header->{length} - 34 - $padding;
    seek $resIn, (tell $resIn) % 4, 1; # Skip record end padding bytes
    open my $strTblIn, '<', \$strTables;

    while (read $strTblIn, (my $hdrData), 6) {

        #struct StringTable {
        #  WORD   wLength;
        #  WORD   wValueLength;
        #  WORD   wType;
        #  WCHAR  szKey[]; // 8 character Unicode string
        #  WORD   Padding[];
        #  String Children[];
        #};

        my %strTblHdr;

        @strTblHdr{qw(length valueLength isText)} = unpack ('vvv', $hdrData);
        read $strTblIn, $strTblHdr{langCP}, 16;
        $strTblHdr{langCP} = Encode::decode ('UTF-16LE', $strTblHdr{langCP});
        seek $strTblIn, (tell $strTblIn) % 4, 1; # Skip padding bytes
        read $strTblIn, (my $stringsData), $strTblHdr{length} - tell $strTblIn;
        open my $stringsIn, '<', \$stringsData;

        while (read $stringsIn, (my $strData), 6) {

            #struct String {
            #  WORD   wLength;
            #  WORD   wValueLength;
            #  WORD   wType;
            #  WCHAR  szKey[];
            #  WORD   Padding[];
            #  WORD   Value[];
            #};

            my %strHdr;

            @strHdr{qw(length valueLength isText)} = unpack ('vvv', $strData);
            read $stringsIn, $strData, $strHdr{length} - 6;
            $strData = Encode::decode ('UTF-16LE', $strData);
            $strData =~ s/\x00\x00+/\x00/g;
            my ($name, $str) = split "\x00", $strData;
            $stringFileInfo{$name} = $str;
            seek $stringsIn, (tell $stringsIn) % 4, 1; # Skip padding bytes
        }
    }

    $rsrcEntry->{StringFileInfo} = \%stringFileInfo;
}


sub _parseVarFileInfo {
    my ($self, $rsrcEntry, $resIn, $header) = @_;

    read $resIn, (my $key), 20;    # remainder of key
    $header->{type} = $header->{type} . Encode::decode ('UTF-16LE', $key);

    my %varFileInfo;

    #struct VarFileInfo {
    #  WORD  wLength;
    #  WORD  wValueLength;
    #  WORD  wType;
    #  WCHAR szKey[]; // "VarFileInfo"
    #  WORD  Padding[];
    #  Var   Children[];
    #};

    my $padding = (tell $resIn) % 4;
    seek $resIn, $padding, 1; # Skip padding bytes following key

    # Read the entire var file info record
    my $pos = tell $resIn;
    read $resIn, (my $varData), $header->{length} - 28 - $padding;
    seek $resIn, (tell $resIn) % 4, 1; # Skip record end padding bytes
    open my $varIn, '<', \$varData;

    while (read $varIn, (my $hdrData), 6) {

        my %varHdr;

        #struct Var {
        #  WORD  wLength;
        #  WORD  wValueLength;
        #  WORD  wType;
        #  WCHAR szKey[];
        #  WORD  Padding[];
        #  DWORD Value[];
        #};

        @varHdr{qw(length valueLength isText)} = unpack ('vvv', $hdrData);
        read $varIn, $varHdr{key}, 22;
        $varHdr{key} = Encode::decode ('UTF-16LE', $varHdr{key});
        my $padding = (tell $varIn) % 4;
        seek $varIn, $padding, 1; # Skip padding bytes following key
        read $varIn, (my $value), $varHdr{length} - 28 - $padding;
        @{$varFileInfo{langCPIds}} = unpack('V*', $value);
    }

    $rsrcEntry->{VarFileInfo} = \%varFileInfo;
}


sub _parseRsrcTable {
    my ($self, $rsrc, $fh, $filePos, $secFilePos, $level) = @_;
    my $oldPos = tell $fh;

    ++$level;
    seek $fh, $filePos + $secFilePos, 0;
    read $fh, (my $rData), 16;

    my %dirTable;

    @dirTable{
        qw(
            Characteristics TimeDate MajorVersion MinorVersion
            NumNameEntries NumIDEntries
            )
        }
        = unpack ('VVvvvv', $rData);

    my ($numNames, $numIDs) = @dirTable{qw(NumNameEntries NumIDEntries)};

    while ($numNames || $numIDs) {
        read $fh, $rData, 8;

        my ($RVAOrID, $RVA) = unpack ('VV', $rData);
        my $addr = ($RVA & ~0x80000000);
        my $rsrcId;

        if ($numNames) {
            # Fetch the entry name. $RVAOrID is the RVA
            --$numNames;
            $rsrcId = _readSzStr ($fh, ($RVAOrID & ~0x80000000) + $secFilePos);

        } elsif ($numIDs) {
            # Resource ID. $RVAOrID is the ID
            --$numIDs;
            $rsrcId = $RVAOrID;
            $rsrcId = $rsrcTypes{$rsrcId}
                if $level == 1 && exists $rsrcTypes{$rsrcId};
        }

        if (0 != ($RVA & 0x80000000)) {
            # It's a sub table entry
            $rsrc->{$rsrcId} = {};
            $self->_parseRsrcTable ($rsrc->{$rsrcId}, $fh, $addr, $secFilePos,
                $level);
        } else {
            # It's a data entry
            $rsrc->{$rsrcId} =
                $self->_readRsrcDataEntry ($fh, $RVA, $secFilePos);
            next;
        }
    }

    seek $fh, $oldPos, 0;
}


sub _readRsrcDataEntry {
    my ($self, $fh, $offset, $secFilePos) = @_;
    my $oldPos = tell $fh;
    my %rsrc;

    seek $fh, $offset + $secFilePos, 0;
    read $fh, my $rData, 16 or die "file read error: $!\n";
    my ($dataRVA, $size, $codePage) = unpack ('VVVV', $rData);
    my $imageRVA      = $self->{COFF}{'!DataDir'}{'.rsrc'}{imageRVA};
    my $resDataOffset = $dataRVA - $imageRVA;

    $rsrc{rsrcCodepage} = $codePage;
    $rsrc{rsrcOffset} = $offset;
    seek $fh, $resDataOffset + $secFilePos, 0;
    read $fh, $rsrc{rsrcData}, $size or die "file read error: $!\n";

    seek $fh, $oldPos, 0;
    return \%rsrc;
}


1;


=head1 NAME

Win32::PEFile - Portable Executable File parser

=head1 SYNOPSIS

    use Win32::PEFile;

    my $pe = Win32::PEFile->new (file => 'someFile.exe');

    print "someFile.exe has a entry point for EntryPoint1"
        if $pe->getEntryPoint ("EntryPoint1");

    my $strings = $pe->getVersionStrings ();
    print "someFile.exe version $strings->{'ProductVersion'}\n";

=head1 Methods

Win32::PEFile provides the following public methods.

=over 4

=item I<new (%parameters)>

Parses a PE file and returns an object used to access the results. The following
parameters may be passed:

=over 4

=item I<-file>: file name, required

The file name (and path if required) of the PE file to process.

=back

=item I<getEntryPoint ($entryPoint)>

Returns true if the given entry point exists in the exports table.

=over 4

=item I<$entryPoint>: required

Name of the entry point to search for in the Exports table of the PE file.

=back

=item I<getVersionStrings ($language)>

Returns a hash reference containing the strings in the version resource keyed
by string name.

=over 4

=item I<$language>: optional

Preferred language for the strings specified as a MicroSoft LangID. US English
is preferred by default.

If the preferred language is not available one of the available languages will
be used instead.

=back

=item I<getFixedVersionValues ($language)>

Returns a hash reference containing the fixed version resource values keyed
by value name.

=over 4

=item I<$language>: optional

Preferred language for the strings specified as a MicroSoft LangID. US English
is preferred by default.

If the preferred language is not available one of the available languages will
be used instead.

=back

=back

=head1 BUGS

Please report any bugs or feature requests to
C<bug-Win32-PEFile at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Win32-PEFile>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

This module is supported by the author through CPAN. The following links may be
of assistance:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Win32-PEFile>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Win32-PEFile>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Win32-PEFile>

=item * Search CPAN

L<http://search.cpan.org/dist/Win32-PEFile>

=back

=head1 SEE ALSO

=head2 Related documentation

http://kishorekumar.net/pecoff_v8.1.htm

=head2 Win32::Exe and Win32::PEFile

Win32::PEFile overlaps in functionality with Win32::Exe. Win32::Exe is a much
more mature module and is more comprehensive. The only current (small)
disadvantages of Win32::Exe are that it is not pure Perl and that has a larger
dependency tree than Win32::PEFile.

For some applications a larger problem with Win32::Exe is that some file editing
operations are not portable across systems.

The intent is that Win32::PEFile will remain pure Perl and low dependency. Over
time PEFile will acquire various editing functions and will remain both cross-
platform and endien agnostic.

=head1 AUTHOR

    Peter Jaquiery
    CPAN ID: GRANDPA
    grandpa@cpan.org

=head1 COPYRIGHT AND LICENSE

This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the
LICENSE file included with this module.

=cut
