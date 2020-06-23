package app.covidshield.utils

import android.util.Log
import com.google.android.apps.exposurenotification.proto.TEKSignatureList
import com.google.android.apps.exposurenotification.proto.TemporaryExposureKeyExport
import com.google.common.io.BaseEncoding
import org.apache.commons.io.IOUtils
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

private const val TAG = "TekLogger"

private const val SIG_FILENAME = "export.sig"
private const val EXPORT_FILENAME = "export.bin"

private val BASE16 = BaseEncoding.base16().lowerCase()
private val BASE64 = BaseEncoding.base64()

fun logTek(files: List<File>) {
    Log.d(TAG, "Logging ${files.size} files.")
    files.forEachIndexed { index, file ->
        val fileContent = readFile(file)

        Log.d(TAG, "File $index has header: ${fileContent.header}")
        Log.d(TAG, "File $index has signature: ${fileContent.signature}")
        Log.d(TAG, "File $index has [${fileContent.export.keysCount}] keys.")

        fileContent.export.keysList.forEach { key ->
            Log.d(TAG,
                ("TEK hex:["
                    + BASE16.encode(key.keyData.toByteArray())
                    ) + "] base64:["
                    + BASE64.encode(key.keyData.toByteArray())
                    .toString() + "] interval_num:["
                    + key.rollingStartIntervalNumber
                    .toString() + "] rolling_period:["
                    + key.rollingPeriod
                    .toString() + "] risk:["
                    + key.transmissionRiskLevel
                    .toString() + "]")
        }
    }
}

private fun readFile(file: File): FileContent {
    val zip = ZipFile(file)
    val signatureEntry: ZipEntry = zip.getEntry(SIG_FILENAME)
    val exportEntry: ZipEntry = zip.getEntry(EXPORT_FILENAME)
    val sigData: ByteArray = IOUtils.toByteArray(zip.getInputStream(signatureEntry))
    val bodyData: ByteArray = IOUtils.toByteArray(zip.getInputStream(exportEntry))
    val header = bodyData.copyOf(16)
    val exportData = bodyData.copyOfRange(16, bodyData.size)
    val headerString = String(header)
    val signature = TEKSignatureList.parseFrom(sigData)
    val export = TemporaryExposureKeyExport.parseFrom(exportData)
    return FileContent(headerString, export, signature)
}

private class FileContent(
    val header: String,
    val export: TemporaryExposureKeyExport,
    val signature: TEKSignatureList
)