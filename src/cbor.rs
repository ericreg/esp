//! CBOR field codecs and strict, size-bounded decoding shared by wire messages
//! and the base64-encoded records in the YAML configuration.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::EndpointId;
use minicbor::{Decode, Decoder, Encode, Encoder, decode, encode};

pub const MAX_VALUE_LEN: usize = u16::MAX as usize;

pub fn decode_exact<'b, T: Decode<'b, ()>>(bytes: &'b [u8]) -> Result<T> {
    if bytes.len() > MAX_VALUE_LEN {
        bail!("CBOR value is too large");
    }
    let mut decoder = Decoder::new(bytes);
    let value = decoder.decode().context("invalid CBOR value")?;
    if decoder.position() != bytes.len() {
        bail!("trailing data after CBOR value");
    }
    Ok(value)
}

pub fn encode_compact<T: Encode<()>>(value: &T) -> Result<String> {
    let bytes = minicbor::to_vec(value).context("failed to encode CBOR value")?;
    if bytes.len() > MAX_VALUE_LEN {
        bail!("CBOR value is too large");
    }
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn decode_compact<T: for<'b> Decode<'b, ()>>(code: &str) -> Result<T> {
    let code = code.trim();
    if code.len() > MAX_VALUE_LEN.div_ceil(3) * 4 {
        bail!("base64 CBOR value is too large");
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(code)
        .context("CBOR value is not valid base64")?;
    decode_exact(&bytes)
}

pub mod endpoint_id {
    use super::*;

    pub fn encode<C, W: encode::Write>(
        value: &EndpointId,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), encode::Error<W::Error>> {
        e.bytes(value.as_bytes())?;
        Ok(())
    }

    pub fn decode<'b, C>(d: &mut Decoder<'b>, _: &mut C) -> Result<EndpointId, decode::Error> {
        let bytes = d
            .bytes()?
            .try_into()
            .map_err(|_| decode::Error::message("endpoint id must be 32 bytes"))?;
        EndpointId::from_bytes(&bytes).map_err(|_| decode::Error::message("invalid endpoint id"))
    }
}

pub mod endpoint_ids {
    use super::*;

    #[derive(Encode, Decode)]
    #[cbor(transparent)]
    struct Id(
        #[n(0)]
        #[cbor(with = "endpoint_id")]
        EndpointId,
    );

    pub fn encode<C, W: encode::Write>(
        values: &[EndpointId],
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), encode::Error<W::Error>> {
        e.array(values.len() as u64)?;
        for value in values {
            endpoint_id::encode(value, e, ctx)?;
        }
        Ok(())
    }

    pub fn decode<'b, C>(d: &mut Decoder<'b>, _: &mut C) -> Result<Vec<EndpointId>, decode::Error> {
        d.array_iter::<Id>()?.map(|id| id.map(|id| id.0)).collect()
    }
}
