import React from 'react';
// material-ui 
import Header from './components/Header/Header';
import Footer from './components/Footer/Footer'
import FormLabel from '@material-ui/core/FormLabel';
import FormControl from '@material-ui/core/FormControl';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Checkbox from '@material-ui/core/Checkbox';
import Container from '@material-ui/core/Container';
import Grid from '@material-ui/core/Grid';
import TextField from '@material-ui/core/TextField';
import IconButton from '@material-ui/core/IconButton';
import Button from '@material-ui/core/Button';
import AutorenewIcon from '@material-ui/icons/Autorenew';
import Tooltip from '@material-ui/core/Tooltip';
import Radio from '@material-ui/core/Radio';
import RadioGroup from '@material-ui/core/RadioGroup';
import FormGroup from '@material-ui/core/FormGroup';
// algorithms
import aesjs from './components/Algorithms/aes';
import SecureRandom from './components/Algorithms/rng';

function App() {
  const [count, setCount] = React.useState('');
  const [iv, setIV] = React.useState('');
  const [key, setKey] = React.useState('');
  const [keysize, setKeySize] = React.useState('128');
  const [mode, setMode] = React.useState('ecb');
  const [plaintext, setPlaintext] = React.useState('');
  const [ciphertext, setCiphertext] = React.useState('');
  const [plaintext2, setPlaintext2] = React.useState('');

  const handleKeySizeChange = (event) => {
    setKeySize(event.target.value);
  };

  const handleModeChange = (event) => {
    setMode(event.target.value);
  };

  const generateKey = () => {
    var size = parseInt(keysize)/8;
    var k = new Uint8Array(size);
    var rng = new SecureRandom();
    var x = [];

    for(var i = 0; i < size; i++){
      x[0] = 0;
      while(x[0] === 0) rng.nextBytes(x);
      k[i] = x[0];
    }
    setKey(aesjs.utils.hex.fromBytes(k));
  }

  const generateCountValue = () => {
    var randnum = Math.floor(Math.random() * (Number.MAX_SAFE_INTEGER)) + 1;
    setCount(randnum.toString());
  }

  const generateIV = () => {
    var iv = new Uint8Array(16);
    var rng = new SecureRandom();
    var x = [];

    for(var i = 0; i < 16; i++){
      x[0] = 0;
      while(x[0] === 0) rng.nextBytes(x);
      iv[i] = x[0];
    }
    setIV(aesjs.utils.hex.fromBytes(iv));
  }

  const encrypt = () => {
    // padding plaintext before encrypting
    var textBytes = aesjs.utils.utf8.toBytes(plaintext);
    var padding = aesjs.padding.pkcs7.pad(textBytes);
    var bytesKey = aesjs.utils.hex.toBytes(key)

    try{
      if(mode === 'ecb'){
        var aesEcb = new aesjs.ModeOfOperation.ecb(bytesKey);
        var encryptedBytes = aesEcb.encrypt(padding);
      } else if(mode === 'cbc'){
        var bytesIV = aesjs.utils.hex.toBytes(iv);
        var aesCbc = new aesjs.ModeOfOperation.cbc(bytesKey, bytesIV);
        var encryptedBytes = aesCbc.encrypt(padding);
      } else if(mode === 'ctr'){
        var c = parseInt(count);
        var aesCtr = new aesjs.ModeOfOperation.ctr(bytesKey, new aesjs.Counter(c));
        var encryptedBytes = aesCtr.encrypt(padding);
      }


      var encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
      setCiphertext(encryptedHex);
      setPlaintext2('')
    } catch(err){
      alert(err);
    }

  }

  const decrypt = () => {
    try{
      var encryptedBytes = aesjs.utils.hex.toBytes(ciphertext);
      var bytesKey = aesjs.utils.hex.toBytes(key)
      if(mode === 'ecb'){
        var aesEcb = new aesjs.ModeOfOperation.ecb(bytesKey);
        var decryptedBytes = aesEcb.decrypt(encryptedBytes);
      } else if(mode === 'cbc'){
        var bytesIV = aesjs.utils.hex.toBytes(iv);
        var aesCbc = new aesjs.ModeOfOperation.cbc(bytesKey, bytesIV);
        var decryptedBytes = aesCbc.decrypt(encryptedBytes);
      } else if(mode === 'ctr'){
        var c = parseInt(count);
        var aesCtr = new aesjs.ModeOfOperation.ctr(bytesKey, new aesjs.Counter(c));
        var decryptedBytes = aesCtr.decrypt(encryptedBytes);
      }
        var unpad = aesjs.padding.pkcs7.strip(decryptedBytes);
        setPlaintext2(aesjs.utils.utf8.fromBytes(unpad));
    } catch(err){
      alert(err);
    }

  }

  const cbc_iv = () => {
    return(
      <Grid container justify="center" alignItems="center" className="mt">
        <Grid item xs={11} md={5}>
          <TextField
            id="outlined-multiline-static"
            label="Initialation Vector (IV) (must be 16 bytes)"
            fullWidth
            multiline
            value={iv}
            variant="outlined"
            onChange={e => setIV(e.target.value)}
          />
        </Grid>
        <Grid item xs={1}>
          <Tooltip title="Generate Random IV">
            <IconButton onClick={generateIV} color="primary" component="span">
              <AutorenewIcon />
            </IconButton>
          </Tooltip>
        </Grid>
      </Grid>
    )
  }
  const count_value = () => {
    return(
      <Grid container justify="center" alignItems="center" className="mt">
        <Grid item xs={11} md={5}>
          <TextField
            id="outlined-multiline-static"
            label="Count Value (must be an integer)"
            fullWidth
            multiline
            value={count}
            variant="outlined"
            onChange={e => setCount(e.target.value)}
          />
        </Grid>
        <Grid item xs={1}>
          <Tooltip title="Generate Random Count Value">
            <IconButton onClick={generateCountValue} color="primary" component="span">
              <AutorenewIcon />
            </IconButton>
          </Tooltip>
        </Grid>
      </Grid>
    )
  }

  return (
    <div className="App">
      <Header
        color="dark"
        routes="/"
        brand="AES Cryptography Demo"
        fixed
        changeColorOnScroll={{
          height: 100,
          color: "rose"
        }}  
      />

      <div>
        <Container>
          <Grid container>
            <Grid item xs={12} md={4} lg={4}>
              <Grid container justify="center" alignItems="center">
                <FormControl component="fieldset">
                  <FormLabel component="legend">Key Size In Bits</FormLabel>
                  <RadioGroup aria-label="keysize" name="keysize" value={keysize} onChange={handleKeySizeChange}>
                    <FormControlLabel value="128" control={<Radio />} label="128" />
                    <FormControlLabel value="192" control={<Radio />} label="192" />
                    <FormControlLabel value="256" control={<Radio />} label="256" />
                  </RadioGroup>
                </FormControl>
              </Grid>
            </Grid>
            <Grid item xs={12} md={4} lg={4}>
              <Grid container justify="center" alignItems="center">
              <FormControl component="fieldset">
                  <FormLabel component="legend">Mode Of Operation</FormLabel>
                  <RadioGroup aria-label="mode" name="mode" value={mode} onChange={handleModeChange}>
                    <FormControlLabel value="ecb" control={<Radio />} label="ECB (Electronic CodeBook)" />
                    <FormControlLabel value="cbc" control={<Radio />} label="CBC (Cipher Block Chaining)" />
                    <FormControlLabel value="ctr" control={<Radio />} label="CTR (Counter)" />
                  </RadioGroup>
                </FormControl>
              </Grid>
            </Grid>
            <Grid item xs={12} md={4} lg={4}>
              <Grid container justify="center" alignItems="center">
                <FormControl component="fieldset">
                  <FormLabel component="legend">Padding</FormLabel>
                  <FormGroup>
                    <FormControlLabel
                      control={<Checkbox checked={true}/>}
                      label="PKCS7"
                    />
                  </FormGroup>
                </FormControl>
              </Grid>
            </Grid>
          </Grid>
        </Container>

        <Container className="mt">
          <Grid container justify="center" alignItems="center">
            <Grid item xs={11} md={6}>
              <TextField
                id="outlined-multiline-static"
                label="Key"
                fullWidth
                multiline
                value={key}
                onChange={e => setKey(e.target.value)}
                variant="outlined"
              />
            </Grid>
            <Grid item xs={1}>
              <Tooltip title="Generate Random Key">
                <IconButton onClick={() => generateKey()} color="primary" component="span">
                  <AutorenewIcon />
                </IconButton>
              </Tooltip>
            </Grid>
          </Grid>
          {mode === 'cbc' ? cbc_iv() : ""}
          {mode === 'ctr' ? count_value() : ""}
        </Container>

        <Container className="mt">
          <Grid container spacing={2} justify="center" alignItems="center">
            <Grid item xs={4}>
              <TextField
                id="outlined-multiline-static"
                label="Plaintext"
                fullWidth
                multiline
                value={plaintext}
                variant="outlined"
                onChange={e => setPlaintext(e.target.value)}
              />
            </Grid>
            <Grid item xs={4}>
              <Grid container alignItems="center" justify="center">
                <Button onClick={encrypt}  variant="contained">Encrypt</Button>
              </Grid>
            </Grid>
            <Grid item xs={4}>
              <TextField
                id="outlined-multiline-static"
                label="Ciphertext"
                fullWidth
                multiline
                value={ciphertext}
                variant="outlined"
              />
            </Grid>
          </Grid>
        </Container>

        <Container className="mt">
          <Grid container spacing={2} justify="center" alignItems="center">
            <Grid item xs={4}>
              <TextField
                id="outlined-multiline-static"
                label="Ciphertext"
                fullWidth
                multiline
                value={ciphertext}
                variant="outlined"
                //onChange={e => setPlainText(e.target.value)}
              />
            </Grid>
            <Grid item xs={4}>
              <Grid container alignItems="center" justify="center">
                <Button onClick={decrypt} variant="contained">Decrypt</Button>
              </Grid>
            </Grid>
            <Grid item xs={4}>
              <TextField
                id="outlined-multiline-static"
                label="Plaintext"
                fullWidth
                multiline
                value={plaintext2}
                variant="outlined"
              />
            </Grid>
          </Grid>
        </Container>

      </div>

      <Footer/>
    </div>
  );
}

export default App;
