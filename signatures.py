import binascii
import struct
import sys
import urllib

from burp import IBurpExtender, ITab, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener
from javax.swing import GroupLayout, JButton, JCheckBox, JLabel, JScrollPane, JOptionPane, JPanel, JTable, JTextField, LayoutStyle, WindowConstants
from javax.swing.event import DocumentListener
from javax.swing.table import DefaultTableModel, TableColumn


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):

        self.name = 'Signatures'
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.name)

        self._initializeGui(callbacks)

        self._factory_messages = IntruderGeneratorFactory(self, "Signatures - Messages")
        self._factory_hashes = IntruderGeneratorFactory(self, "Signatures - Hashes")
        self._factory_padding = IntruderGeneratorFactory(self, "Signatures - Padding only")
        callbacks.registerIntruderPayloadGeneratorFactory(self._factory_messages)
        callbacks.registerIntruderPayloadGeneratorFactory(self._factory_hashes)
        callbacks.registerIntruderPayloadGeneratorFactory(self._factory_padding)

    def _initializeGui(self, callbacks):
        tab = JPanel()

        jLabel1 = JLabel("Original Hash:")
        jLabel2 = JLabel("Original message:")
        jLabel3 = JLabel("Message to append:")
        jLabel5 = JLabel("Max key length:")
        jTextField1 = JTextField("")
        jTextField2 = JTextField("")
        jTextField3 = JTextField("")
        jTextField4 = JTextField("128")
        jLabel4 = JLabel("Hashing functions")
        jCheckBox1 = JCheckBox("MD4")
        jCheckBox2 = JCheckBox("MD5")
        jCheckBox3 = JCheckBox("SHA1")
        jCheckBox4 = JCheckBox("SHA256")
        jCheckBox5 = JCheckBox("SHA512")
        jCheckBox1.setEnabled(False)
        jCheckBox2.setEnabled(False)
        jCheckBox3.setEnabled(False)
        jCheckBox4.setEnabled(False)
        jCheckBox5.setEnabled(False)
        jScrollPane1 = JScrollPane()
        jTable1 = JTable()
        jButton1 = JButton("Generate", actionPerformed=self.generate_attack)
        jButton1.setEnabled(False)
        jButton2 = JButton("Copy messages", actionPerformed=self.copy_messages)
        jButton3 = JButton("Copy hashes", actionPerformed=self.copy_hashes)

        self._tab = tab
        self._textfields = {
            "original_hash": jTextField1,
            "original_msg": jTextField2,
            "append_msg": jTextField3,
            "max_key_len": jTextField4,
        }
        self._checkboxes = {
            md4: jCheckBox1,
            md5: jCheckBox2,
            sha1: jCheckBox3,
            sha256: jCheckBox4,
            sha512: jCheckBox5,
        }

        self._table = jTable1
        self._extensions = {}
        self._hashes, self._messages = [], []

        # Hash field change event
        jTextField1.getDocument().addDocumentListener(HashChangeListener(self._checkboxes, self._textfields['original_hash'], jButton1))

        # Table columns
        jTable1.setModel(DefaultTableModel([],["#", "Type","New Message", "Hash"]))
        jScrollPane1.setViewportView(jTable1)
        # Table column width
        jTable1.getColumnModel().getColumn(0).setMaxWidth(50)
        jTable1.getColumnModel().getColumn(1).setMaxWidth(60)

        layout = GroupLayout(tab)
        tab.setLayout(layout)

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(24, 24, 24)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                    .addComponent(jLabel5)
                    .addComponent(jLabel1)
                    .addComponent(jLabel2)
                    .addComponent(jLabel3))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(jTextField3, GroupLayout.DEFAULT_SIZE, 425, 32767)
                    .addComponent(jTextField2)
                    .addComponent(jTextField1)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jTextField4, GroupLayout.PREFERRED_SIZE, 88, GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, 32767)))
                .addGap(30, 30, 30)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jCheckBox1)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jCheckBox2)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jCheckBox3)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jCheckBox4)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jCheckBox5))
                    .addComponent(jLabel4)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jButton1)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton3)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton2)))
                .addGap(167, 167, 167))
            .addComponent(jScrollPane1)
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(26, 26, 26)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(jTextField1, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel4))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(jTextField2, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(jCheckBox2)
                        .addComponent(jCheckBox3)
                        .addComponent(jCheckBox1)
                        .addComponent(jCheckBox4)
                        .addComponent(jCheckBox5)))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(jTextField3, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5)
                    .addComponent(jTextField4, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton2)
                    .addComponent(jButton3)
                    .addComponent(jButton1))
                .addGap(13, 13, 13)
                .addComponent(jScrollPane1, GroupLayout.DEFAULT_SIZE, 971, 32767))
        )

        callbacks.customizeUiComponent(tab)
        callbacks.addSuiteTab(self)

    def getUiComponent(self):
        return self._tab

    def getTabCaption(self):
        return self.name

    def generate_attack(self, actionEvent):
        if self._validate_form():

            original_hash = hex_to_raw(self._textfields["original_hash"].getText())
            original_msg = self._textfields["original_msg"].getText().encode()
            append_msg = self._textfields["append_msg"].getText().encode()
            max_key_len = int(self._textfields["max_key_len"].getText())
        
            hash_functions = [hash_function for hash_function in self._checkboxes if self._checkboxes[hash_function].isSelected()]

            extensions = {}
            for hash_function in hash_functions:
                extensions[hash_function] = length_extension(hash_function, original_hash, original_msg, append_msg, max_key_len)

            self._extensions = extensions
            self._hashes, self._messages, self._padding = [], [], []

            model = self._table.getModel()

            # Removes all table entries
            model.setRowCount(0)
            i = 1
            for hash_function in extensions:
                for row in extensions[hash_function]:
                    model.addRow([i, hash_function.__name__.upper(), row['msg'], row['tag']])
                    self._messages.append(row['msg'])
                    self._hashes.append(row['tag'])
                    self._padding.append(row['pad'])
                    i += 1

            self._factory_padding.set_payload(self._padding)
            self._factory_messages.set_payload(self._messages)
            self._factory_hashes.set_payload(self._hashes)

    def _validate_form(self):
        error_message = ''

        try:
            original_hash = hex_to_raw(self._textfields["original_hash"].getText())
        except Exception:
            error_message += "Original hash doesn't look right.\n"

        try:
            max_key_len = int(self._textfields["max_key_len"].getText())
        except Exception:
            error_message += "Max key length needs to be an integer.\n"

        original_msg = self._textfields["original_msg"].getText().encode()
        append_msg = self._textfields["append_msg"].getText().encode()

        if not original_msg:
            error_message += "Missing original message.\n"
        if not append_msg:
            error_message += "Missing message to append.\n"

        if error_message:
            JOptionPane.showMessageDialog(self._tab, error_message, "Form Validation Error", JOptionPane.WARNING_MESSAGE)
            return False
        return True

    def copy_hashes(self, actionEvent):
        if self._hashes:
            string_selection = StringSelection('\n'.join(self._hashes))
            clpbrd = Toolkit.getDefaultToolkit().getSystemClipboard()
            clpbrd.setContents(string_selection, None)

    def copy_messages(self, actionEvent):
        if self._messages:
            string_selection = StringSelection('\n'.join(self._messages))
            clpbrd = Toolkit.getDefaultToolkit().getSystemClipboard()
            clpbrd.setContents(string_selection, None)

class HashChangeListener(DocumentListener):
    def __init__(self, checkboxes, original_hash_textfield, run_button):
        self._checkboxes = checkboxes
        self._original_hash_textfield = original_hash_textfield
        self._run_button = run_button

    def changedUpdate(self, e):
        self.stateChanged()

    def removeUpdate(self, e):
        self.stateChanged()

    def insertUpdate(self, e):
        self.stateChanged()

    def stateChanged(self):
        # Unselect all checkboxes
        for c in self._checkboxes:
            self._checkboxes[c].setSelected(False)
            self._checkboxes[c].setEnabled(False)
            self._run_button.setEnabled(False)
        try:
            original_hash = hex_to_raw(self._original_hash_textfield.getText())
            hash_functions = guess_hash_type(original_hash)
            for h in hash_functions:
                self._run_button.setEnabled(True)
                self._checkboxes[h].setSelected(True)
                self._checkboxes[h].setEnabled(True)
        except Exception as e:
            pass

class IntruderGeneratorFactory(IIntruderPayloadGeneratorFactory):
    def __init__(self, extender, name):
        self.extender = extender
        self.name = name
        self.payloads = ()

    def set_payload(self, payloads):
        self.payloads = payloads

    def getGeneratorName(self):
        return self.name

    def createNewInstance(self, attack):
        if self.payloads:
            return IntruderGenerator(self.extender, attack, self.payloads)

class IntruderGenerator(IIntruderPayloadGenerator):
    def __init__(self, extender, attack, payloads):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.payloads = payloads
        self.iterations = 0

    def hasMorePayloads(self):
        return False if self.iterations == len(self.payloads) else True

    def getNextPayload(self, current_payload):
        payload = self.payloads[self.iterations]
        self.iterations += 1
        return payload

# Custom crypto library

def length_extension(hash_function, original_tag, original_msg, append_msg, max_key_len=64):
    if not isinstance(original_tag, bytes):
        original_tag = hex_to_raw(original_tag)

    endianess = '<' if hash_function in [md4, md5] else '>'

    if hash_function in [sha512]:
        struct_settings = '>8Q'
        padding = md_padding_sha512
    else:
        struct_settings = endianess + str(len(original_tag)//4) + 'L'
        padding = md_padding

    h = struct.unpack(struct_settings, original_tag)

    msg_tag_pairs = []

    for key_length in range(max_key_len):
        pad = padding(len(b'a'*key_length + original_msg), endianess)
        msg = original_msg + pad + append_msg
        tag = hash_function(append_msg, h, len(msg) + key_length)
        msg_tag_pairs.append({'msg':msg, 'tag':tag, 'pad':pad})

    return msg_tag_pairs

def guess_hash_type(thishash):
    # Guesses likely hashing algorithm based on hash length
    if not isinstance(thishash, bytes):
        thishash = hex_to_raw(thishash)

    if len(thishash) == 16:
        return [md4, md5]
    elif len(thishash) == 20:
        return [sha1]
    elif len(thishash) == 32:
        return [sha256]
    elif len(thishash) == 64:
        return [sha512]

def raw_to_b64(raw):
    return binascii.b2a_base64(raw).rstrip()

def b64_to_raw(b64_string):
    return binascii.a2b_base64(b64_string)

def raw_to_hex(raw):
    return binascii.hexlify(bytes(raw)).decode('utf-8')

def raw_to_ascii(raw):
    return ''.join([chr(b) for b in raw])

def hex_to_raw(hex_string):
    return binascii.unhexlify(hex_string)

def ascii_to_raw(ascii_string):
    return ascii_string.encode()

def _left_rotate(n, b):
    # Left rotate a 32-bit integer n by b bits
    return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff

def _right_rotate(n, b):
    # Right rotate a 32-bit integer n by n bits
    return ((n >> b) | (n << (32 - b))) & 0xffffffff

def _right_rotate_64(n, b):
    # Right rotate a 64-bit integer n by n bits
    return ((n >> b) | (n << (64 - b))) & 0xffffffffffffffff

def md_padding(msg_length, endianess='>', block_size=64):
    return b''.join([
        b'\x80',
        b'\x00' * ((block_size - 9 - (msg_length % block_size)) % block_size), 
        struct.pack(endianess + '1Q', msg_length << 3)
    ])

def md_padding_sha512(msg_length, endianess='>'):
    mdi = msg_length % 128
    padlen = (119-mdi) if mdi < 112 else (247-mdi)
    return b''.join([
        b'\x80',
        b'\x00' * padlen,
        struct.pack(endianess + '1Q', msg_length << 3)
    ])

def sha1(msg, state=(0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0), fake_len=0, raw=False):
    # source https://github.com/ajalt/python-sha1/blob/master/sha1.py

    def _process_chunk(chunk, h0, h1, h2, h3, h4):
        # Process a chunk of data and return the new digest variables.
        assert len(chunk) == 64

        w = [0] * 80

        w[:16] = struct.unpack('>16L', chunk)

        # Extend the sixteen 4-byte words into eighty 4-byte words
        for i in range(16, 80):
            w[i] = _left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
        
        # Initialize hash value for this chunk
        a, b, c, d, e = h0, h1, h2, h3, h4
        
        for i in range(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
        
            a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, 
                            a, _left_rotate(b, 30), c, d)
        
        # Add this chunk's hash to result so far
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

        return h0, h1, h2, h3, h4

    msg = ascii_to_raw(msg)
    msg += md_padding(fake_len or len(msg))

    while msg:
        state = _process_chunk(msg[:64], *state)
        msg = msg[64:]
    
    output = struct.pack('>5I', *state)
    return output if raw else raw_to_hex(output)

def sha256(msg, state=(0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19), fake_len=0, raw=False):

    k = (
       0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
       0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
       0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
       0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
       0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
       0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
       0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
       0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
   )

    def _process_chunk(chunk, h0, h1, h2, h3, h4, h5, h6, h7):
        w = [0]*64

        w[:16] = struct.unpack('>16L', chunk)

        for i in range(16, 64):
            s0 = _right_rotate(w[i-15], 7) ^ _right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = _right_rotate(w[i-2], 17) ^ _right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff
        
        a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7

        for i in range(64):
            s0 = _right_rotate(a, 2) ^ _right_rotate(a, 13) ^ _right_rotate(a, 22)
            s1 = _right_rotate(e, 6) ^ _right_rotate(e, 11) ^ _right_rotate(e, 25)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + k[i] + w[i]
            
            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff
        
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
        h5 = (h5 + f) & 0xffffffff
        h6 = (h6 + g) & 0xffffffff
        h7 = (h7 + h) & 0xffffffff
        return h0, h1, h2, h3, h4, h5, h6, h7

    msg = ascii_to_raw(msg)
    msg += md_padding(fake_len or len(msg))

    while msg:
        state = _process_chunk(msg[:64], *state)
        msg = msg[64:]

    output = struct.pack('>8I', *state)
    return output if raw else raw_to_hex(output)

def sha224(msg, state=(0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4), fake_len=0, raw=False):
    # Reuses sha256 implementation
    state_from_sha256 = struct.unpack('>8I', sha256(msg, state, fake_len, raw=True))
    output = struct.pack('>7I', *state_from_sha256[:-1])
    return output if raw else raw_to_hex(output)

def sha512(msg, state=(0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179), fake_len=0, raw=False):
    k = (

        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
        0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
        0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
        0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
        0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
        0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
        0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    )

    def _process_chunk(chunk, h0, h1, h2, h3, h4, h5, h6, h7):
        w = [0]*80
        w[:16] = struct.unpack('>16Q', chunk)

        for i in range(16, 80):
            s0 = _right_rotate_64(w[i-15], 1) ^ _right_rotate_64(w[i-15], 8) ^ (w[i-15] >> 7)
            s1 = _right_rotate_64(w[i-2], 19) ^ _right_rotate_64(w[i-2], 61) ^ (w[i-2] >> 6)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffffffffffff
        
        a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7

        for i in range(80):
            s0 = _right_rotate_64(a, 28) ^ _right_rotate_64(a, 34) ^ _right_rotate_64(a, 39)
            s1 = _right_rotate_64(e, 14) ^ _right_rotate_64(e, 18) ^ _right_rotate_64(e, 41)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + k[i] + w[i]
            
            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffffffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffffffffffff
        
        h0 = (h0 + a) & 0xffffffffffffffff
        h1 = (h1 + b) & 0xffffffffffffffff
        h2 = (h2 + c) & 0xffffffffffffffff
        h3 = (h3 + d) & 0xffffffffffffffff
        h4 = (h4 + e) & 0xffffffffffffffff
        h5 = (h5 + f) & 0xffffffffffffffff
        h6 = (h6 + g) & 0xffffffffffffffff
        h7 = (h7 + h) & 0xffffffffffffffff
        return h0, h1, h2, h3, h4, h5, h6, h7

    msg = ascii_to_raw(msg)
    msg += md_padding_sha512(fake_len or len(msg))

    while msg:
        state = _process_chunk(msg[:128], *state)
        msg = msg[128:]

    output = struct.pack('>8Q', *state)
    return output if raw else raw_to_hex(output)

def md4(msg, state=(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476), fake_len=0, raw=False):
    # source http://www.acooke.org/cute/PurePython0.html
    def f(x, y, z): return x & y | ~x & z
    def g(x, y, z): return x & y | x & z | y & z
    def h(x, y, z): return x ^ y ^ z
    def f1(a, b, c, d, k, s, X): return _left_rotate(a + f(b, c, d) + X[k], s)
    def f2(a, b, c, d, k, s, X): return _left_rotate(a + g(b, c, d) + X[k] + 0x5a827999, s)
    def f3(a, b, c, d, k, s, X): return _left_rotate(a + h(b, c, d) + X[k] + 0x6ed9eba1, s)
    
    def _process_chunk(x, h0, h1, h2, h3):
        a, b, c, d = h0, h1, h2, h3
        
        x = struct.unpack('<16L', x)

        a = f1(a,b,c,d, 0, 3, x)
        d = f1(d,a,b,c, 1, 7, x)
        c = f1(c,d,a,b, 2,11, x)
        b = f1(b,c,d,a, 3,19, x)
        a = f1(a,b,c,d, 4, 3, x)
        d = f1(d,a,b,c, 5, 7, x)
        c = f1(c,d,a,b, 6,11, x)
        b = f1(b,c,d,a, 7,19, x)
        a = f1(a,b,c,d, 8, 3, x)
        d = f1(d,a,b,c, 9, 7, x)
        c = f1(c,d,a,b,10,11, x)
        b = f1(b,c,d,a,11,19, x)
        a = f1(a,b,c,d,12, 3, x)
        d = f1(d,a,b,c,13, 7, x)
        c = f1(c,d,a,b,14,11, x)
        b = f1(b,c,d,a,15,19, x)

        a = f2(a,b,c,d, 0, 3, x)
        d = f2(d,a,b,c, 4, 5, x)
        c = f2(c,d,a,b, 8, 9, x)
        b = f2(b,c,d,a,12,13, x)
        a = f2(a,b,c,d, 1, 3, x)
        d = f2(d,a,b,c, 5, 5, x)
        c = f2(c,d,a,b, 9, 9, x)
        b = f2(b,c,d,a,13,13, x)
        a = f2(a,b,c,d, 2, 3, x)
        d = f2(d,a,b,c, 6, 5, x)
        c = f2(c,d,a,b,10, 9, x)
        b = f2(b,c,d,a,14,13, x)
        a = f2(a,b,c,d, 3, 3, x)
        d = f2(d,a,b,c, 7, 5, x)
        c = f2(c,d,a,b,11, 9, x)
        b = f2(b,c,d,a,15,13, x)

        a = f3(a,b,c,d, 0, 3, x)
        d = f3(d,a,b,c, 8, 9, x)
        c = f3(c,d,a,b, 4,11, x)
        b = f3(b,c,d,a,12,15, x)
        a = f3(a,b,c,d, 2, 3, x)
        d = f3(d,a,b,c,10, 9, x)
        c = f3(c,d,a,b, 6,11, x)
        b = f3(b,c,d,a,14,15, x)
        a = f3(a,b,c,d, 1, 3, x)
        d = f3(d,a,b,c, 9, 9, x)
        c = f3(c,d,a,b, 5,11, x)
        b = f3(b,c,d,a,13,15, x)
        a = f3(a,b,c,d, 3, 3, x)
        d = f3(d,a,b,c,11, 9, x)
        c = f3(c,d,a,b, 7,11, x)
        b = f3(b,c,d,a,15,15, x)

        return [(h0 + a) & 0xffffffff, (h1 + b) & 0xffffffff, (h2 + c) & 0xffffffff, (h3 + d) & 0xffffffff]

    msg = ascii_to_raw(msg)
    msg += md_padding(fake_len or len(msg), '<')

    while msg:
        state = _process_chunk(msg[:64], *state)
        msg = msg[64:]

    output = struct.pack('<4I', *state)
    return output if raw else raw_to_hex(output)

def md5(msg, state=(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476), fake_len=0, raw=False):
    s = (
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
    )

    K = (
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    )

    def _process_chunk(x, h0, h1, h2, h3):
        a, b, c, d = h0, h1, h2, h3
        
        X = struct.unpack('<16L', x)

        for i in range(64):
            if 0 <= i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                f = (d & b) | (~d & c)
                g = (5*i + 1) % 16
            elif 32 <= i <= 47:
                f = b ^ c ^ d
                g = (3*i + 5) % 16
            elif 48 <= i <= 63:
                f = c ^ (b | ~d)
                g = (7*i) % 16
            
            dtemp = d
            d = c
            c = b
            b = b + _left_rotate((a + f + K[i] + X[g]), s[i])
            a = dtemp

        return [(h0 + a) & 0xffffffff, (h1 + b) & 0xffffffff, (h2 + c) & 0xffffffff, (h3 + d) & 0xffffffff]

    msg = ascii_to_raw(msg)
    msg += md_padding(fake_len or len(msg), '<')

    while msg:
        state = _process_chunk(msg[:64], *state)
        msg = msg[64:]

    output = struct.pack('<4I', *state)
    return output if raw else raw_to_hex(output)