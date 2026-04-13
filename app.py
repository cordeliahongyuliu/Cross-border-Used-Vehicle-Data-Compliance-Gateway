import hashlib
import json
from datetime import datetime
from io import BytesIO

import pandas as pd
import streamlit as st


WHITE_LIST = [
    "vin_code",
    "brand_model",
    "engine_displacement",
    "manufacture_date",
    "mileage",
    "accident_summary",
]
GRAY_LIST = ["owner_name", "repair_shop", "phone_number"]
BLACK_LIST = ["gps_track", "id_card", "address"]

COLUMN_ALIASES = {
    "vin_code": ["vin_code", "vin", "vin码", "车架号", "车辆识别码"],
    "brand_model": ["brand_model", "brand", "model", "品牌型号", "车型"],
    "engine_displacement": ["engine_displacement", "排量"],
    "manufacture_date": ["manufacture_date", "生产日期", "出厂日期"],
    "mileage": ["mileage", "里程"],
    "accident_summary": ["accident_summary", "事故概况", "事故摘要"],
    "owner_name": ["owner_name", "车主姓名", "姓名"],
    "repair_shop": ["repair_shop", "维修厂", "修理厂"],
    "phone_number": ["phone_number", "手机号", "联系电话", "电话"],
    "gps_track": ["gps_track", "gps", "轨迹"],
    "id_card": ["id_card", "身份证", "身份证号"],
    "address": ["address", "地址"],
}

STEP_LABELS = [
    "1. 数据准备",
    "2. 原始数据预览",
    "3. 数据脱敏",
    "4. 哈希链存证",
    "5. VIN篡改验证",
    "6. 生成可信证书",
]


def normalize_header(text):
    if text is None:
        return ""
    return str(text).strip().lower().replace(" ", "").replace("_", "")


def normalize_vin(value):
    if value is None or pd.isna(value):
        return ""
    text = str(value).strip().upper()
    if text.endswith(".0") and text[:-2].isdigit():
        return text[:-2]
    return text


def normalize_value(value):
    if value is None or pd.isna(value):
        return ""
    text = str(value).strip()
    if text.endswith(".0") and text[:-2].isdigit():
        return text[:-2]
    return text


def map_columns(df):
    normalized_to_real = {normalize_header(col): col for col in df.columns}
    rename_map = {}
    for std_name, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            key = normalize_header(alias)
            if key in normalized_to_real:
                rename_map[normalized_to_real[key]] = std_name
                break
    return df.rename(columns=rename_map)


def init_session_state():
    if "raw_df" not in st.session_state:
        st.session_state.raw_df = None
    if "masked_df" not in st.session_state:
        st.session_state.masked_df = None
    if "hashed_df" not in st.session_state:
        st.session_state.hashed_df = None
    if "uploaded_signature" not in st.session_state:
        st.session_state.uploaded_signature = None
    if "current_step" not in st.session_state:
        st.session_state.current_step = 0


def reset_pipeline_state():
    st.session_state.masked_df = None
    st.session_state.hashed_df = None


def load_excel(source):
    df = pd.read_excel(source, dtype=str)
    df = map_columns(df)
    if "vin_code" in df.columns:
        df["vin_code"] = df["vin_code"].apply(normalize_vin)
    return df


def try_load_excel(source):
    try:
        return load_excel(source), None
    except Exception as e:
        return None, str(e)


def desensitize_data(df):
    processed_df = df.copy()
    drop_cols = [col for col in BLACK_LIST if col in processed_df.columns]
    if drop_cols:
        processed_df = processed_df.drop(columns=drop_cols)

    if "owner_name" in processed_df.columns:
        processed_df["owner_name"] = "张**三"
    if "phone_number" in processed_df.columns:
        processed_df["phone_number"] = "138****5678"
    if "repair_shop" in processed_df.columns:
        processed_df["repair_shop"] = "anonymized"

    keep_cols = [col for col in WHITE_LIST + GRAY_LIST if col in processed_df.columns]
    processed_df = processed_df[keep_cols].copy()
    processed_df["compliance_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    processed_df["compliance_status"] = "passed"
    return processed_df


def get_hash_columns(df):
    base_cols = WHITE_LIST + GRAY_LIST + ["compliance_timestamp", "compliance_status"]
    return [col for col in base_cols if col in df.columns]


def row_payload(row, hash_cols):
    payload = {}
    for col in hash_cols:
        value = row[col] if col in row.index else ""
        if col == "vin_code":
            payload[col] = normalize_vin(value)
        else:
            payload[col] = normalize_value(value)
    return payload


def calc_hash_steps(payload):
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    h1 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    h2 = hashlib.sha256((h1 + "合规通过").encode("utf-8")).hexdigest()
    h3 = hashlib.sha256((h2 + "出口事件确认").encode("utf-8")).hexdigest()
    return h1, h2, h3


def build_hash_chain(df):
    result_df = df.copy()
    hash_cols = get_hash_columns(result_df)
    hashes = []
    for _, row in result_df.iterrows():
        _, _, h3 = calc_hash_steps(row_payload(row, hash_cols))
        hashes.append(h3)
    result_df["hash"] = hashes
    return result_df


def verify_by_vin(df_with_hash, vin_input):
    if "vin_code" not in df_with_hash.columns:
        return "验证失败：数据中没有 vin_code 列"
    if "hash" not in df_with_hash.columns:
        return "验证失败：数据中没有 hash 列"

    query_vin = normalize_vin(vin_input)
    if query_vin == "":
        return "验证失败：VIN 不能为空"

    candidates = df_with_hash[df_with_hash["vin_code"].apply(normalize_vin) == query_vin]
    if candidates.empty:
        return "验证失败：未找到该 VIN"

    hash_cols = get_hash_columns(df_with_hash)
    for _, row in candidates.iterrows():
        current_hash = normalize_value(row.get("hash", ""))
        _, _, recalculated = calc_hash_steps(row_payload(row, hash_cols))
        if current_hash == recalculated:
            return "数据真实有效"
    return "数据已被篡改"


@st.cache_data
def build_embedded_default_df():
    rows = [
        ["LSVPC69ZCANLP5PC2", "大众 帕萨特", "1.8T", "2019-05-21", "65000", "轻微剐蹭已修复", "张三", "成都某维修中心", "13812345678", "四川省成都市高新区"],
        ["LFV2A2157K3000888", "奥迪 A6L", "2.0T", "2018-11-12", "82000", "无重大事故", "李四", "天府汽修厂", "13912345678", "四川省成都市武侯区"],
        ["LGBH52E01KY123456", "本田 雅阁", "1.5T", "2020-03-18", "41000", "无重大事故", "王五", "锦江汽修", "13712345678", "四川省成都市锦江区"],
        ["WVWZZZ3CZEE000777", "大众 途观", "2.0T", "2017-07-09", "92000", "右侧补漆", "赵六", "青羊维修站", "13612345678", "四川省成都市青羊区"],
        ["LNBSCMCE0KH223344", "宝马 320Li", "2.0T", "2019-09-01", "58000", "无重大事故", "孙七", "高新车服", "13512345678", "四川省成都市高新区"],
        ["LSGUA84L9JF765432", "别克 君威", "1.5T", "2018-01-30", "76000", "后杠更换", "周八", "武侯快修", "13412345678", "四川省成都市武侯区"],
        ["LDC613P23K1098765", "丰田 凯美瑞", "2.0L", "2021-06-14", "32000", "无重大事故", "吴九", "成华汽修", "13312345678", "四川省成都市成华区"],
        ["LSJA24U68GG556677", "日产 天籁", "2.0L", "2016-10-25", "105000", "左后门钣金", "郑十", "金牛修理厂", "13212345678", "四川省成都市金牛区"],
    ]
    data = []
    for i, r in enumerate(rows, start=1):
        data.append(
            {
                "vin_code": r[0],
                "brand_model": r[1],
                "engine_displacement": r[2],
                "manufacture_date": r[3],
                "mileage": r[4],
                "accident_summary": r[5],
                "owner_name": r[6],
                "repair_shop": r[7],
                "phone_number": r[8],
                "gps_track": f"104.{i:02d},30.{60+i}|104.{i+1:02d},30.{61+i}",
                "id_card": f"510{i}************",
                "address": r[9],
            }
        )
    df = pd.DataFrame(data)
    df = map_columns(df)
    if "vin_code" in df.columns:
        df["vin_code"] = df["vin_code"].apply(normalize_vin)
    return df


@st.cache_data
def get_embedded_default_excel_bytes():
    # Used only for download. If excel engine is missing, return None and keep page alive.
    try:
        df = build_embedded_default_df()
        bio = BytesIO()
        df.to_excel(bio, index=False)
        return bio.getvalue()
    except Exception:
        return None


def load_embedded_default_df():
    # Always available without file path dependency.
    return build_embedded_default_df()


def go_next_if_allowed(allowed):
    if allowed and st.button("➡️ 下一步", use_container_width=True):
        st.session_state.current_step = min(st.session_state.current_step + 1, len(STEP_LABELS) - 1)
        st.rerun()


@st.dialog("验证结果")
def show_verify_dialog(message):
    if "数据真实有效" in message:
        st.success(message, icon="✅")
    else:
        st.error(message, icon="❌")


def render_sidebar():
    st.sidebar.title("流程向导")
    selected = st.sidebar.radio(
        "步骤导航",
        STEP_LABELS,
        index=st.session_state.current_step,
        label_visibility="collapsed",
    )
    st.session_state.current_step = STEP_LABELS.index(selected)
    p = (st.session_state.current_step + 1) / len(STEP_LABELS)
    st.sidebar.progress(p, text=f"当前进度：{st.session_state.current_step + 1}/{len(STEP_LABELS)}")


def find_row_by_vin(df, vin_input):
    if df is None or "vin_code" not in df.columns:
        return None
    vin = normalize_vin(vin_input)
    if vin == "":
        return None
    hit = df[df["vin_code"].apply(normalize_vin) == vin]
    if hit.empty:
        return None
    return hit.iloc[0]


def build_certificate_dict(row):
    hash_cols = get_hash_columns(pd.DataFrame([row]))
    payload = row_payload(row, hash_cols)
    h1, h2, h3 = calc_hash_steps(payload)
    cert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "title": "二手车跨境数据可信存证证书",
        "generate_time": cert_time,
        "vin_code": normalize_value(row.get("vin_code", "")),
        "brand_model": normalize_value(row.get("brand_model", "")),
        "engine_displacement": normalize_value(row.get("engine_displacement", "")),
        "manufacture_date": normalize_value(row.get("manufacture_date", "")),
        "mileage": normalize_value(row.get("mileage", "")),
        "accident_summary": normalize_value(row.get("accident_summary", "")),
        "owner_name": normalize_value(row.get("owner_name", "")),
        "repair_shop": normalize_value(row.get("repair_shop", "")),
        "phone_number": normalize_value(row.get("phone_number", "")),
        "compliance_timestamp": normalize_value(row.get("compliance_timestamp", cert_time)),
        "compliance_status": normalize_value(row.get("compliance_status", "passed")),
        "h1": h1,
        "h2": h2,
        "h3": h3,
    }


def render_certificate_preview(cert):
    html = f"""
    <div style="background:#f5f7fb;padding:18px;border-radius:10px;display:flex;justify-content:center;">
      <div style="width:794px;min-height:1123px;background:#fff;border:1px solid #d0d7e2;padding:40px 56px;
                  box-shadow:0 4px 16px rgba(0,0,0,0.08);font-family:Arial,'Microsoft YaHei',sans-serif;color:#1f2937;">
        <h1 style="text-align:center;margin:0 0 8px 0;font-size:30px;">{cert['title']}</h1>
        <div style="text-align:center;color:#4b5563;margin-bottom:24px;">证书生成时间：{cert['generate_time']}</div>
        <hr style="border:none;border-top:2px solid #2563eb;margin:0 0 20px 0;">
        <h3 style="margin:0 0 12px 0;">车辆关键信息</h3>
        <table style="width:100%;border-collapse:collapse;margin-bottom:18px;">
          <tr><td style="padding:8px;border:1px solid #e5e7eb;">VIN</td><td style="padding:8px;border:1px solid #e5e7eb;">{cert['vin_code']}</td></tr>
          <tr><td style="padding:8px;border:1px solid #e5e7eb;">品牌型号</td><td style="padding:8px;border:1px solid #e5e7eb;">{cert['brand_model']}</td></tr>
          <tr><td style="padding:8px;border:1px solid #e5e7eb;">排量</td><td style="padding:8px;border:1px solid #e5e7eb;">{cert['engine_displacement']}</td></tr>
          <tr><td style="padding:8px;border:1px solid #e5e7eb;">生产日期</td><td style="padding:8px;border:1px solid #e5e7eb;">{cert['manufacture_date']}</td></tr>
          <tr><td style="padding:8px;border:1px solid #e5e7eb;">里程</td><td style="padding:8px;border:1px solid #e5e7eb;">{cert['mileage']}</td></tr>
          <tr><td style="padding:8px;border:1px solid #e5e7eb;">事故概况</td><td style="padding:8px;border:1px solid #e5e7eb;">{cert['accident_summary']}</td></tr>
        </table>
        <h3 style="margin:0 0 12px 0;">脱敏后数据</h3>
        <table style="width:100%;border-collapse:collapse;margin-bottom:18px;">
          <tr><td style="padding:8px;border:1px solid #e5e7eb;">车主姓名</td><td style="padding:8px;border:1px solid #e5e7eb;">{cert['owner_name']}</td></tr>
          <tr><td style="padding:8px;border:1px solid #e5e7eb;">维修机构</td><td style="padding:8px;border:1px solid #e5e7eb;">{cert['repair_shop']}</td></tr>
          <tr><td style="padding:8px;border:1px solid #e5e7eb;">联系电话</td><td style="padding:8px;border:1px solid #e5e7eb;">{cert['phone_number']}</td></tr>
        </table>
        <h3 style="margin:0 0 12px 0;">哈希链存证</h3>
        <div style="font-size:12px;line-height:1.5;word-break:break-all;border:1px solid #e5e7eb;padding:10px;border-radius:6px;">
          <div><b>h1</b>: {cert['h1']}</div>
          <div><b>h2</b>: {cert['h2']}</div>
          <div><b>h3</b>: {cert['h3']}</div>
        </div>
        <div style="margin-top:18px;border-top:1px solid #e5e7eb;padding-top:12px;color:#374151;">
          合规处理时间：{cert['compliance_timestamp']}<br/>
          合规状态：{cert['compliance_status']}
        </div>
      </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def generate_pdf_bytes(cert):
    lines = [
        "Used Car Cross-border Trusted Data Certificate",
        "",
        f"VIN: {cert['vin_code']}",
        f"Brand Model: {cert['brand_model']}",
        f"Engine: {cert['engine_displacement']}",
        f"Manufacture Date: {cert['manufacture_date']}",
        f"Mileage: {cert['mileage']}",
        f"Accident Summary: {cert['accident_summary']}",
        "",
        "Desensitized Data:",
        f"Owner: {cert['owner_name']}",
        f"Repair Shop: {cert['repair_shop']}",
        f"Phone: {cert['phone_number']}",
        "",
        "Hash Chain:",
        f"h1: {cert['h1']}",
        f"h2: {cert['h2']}",
        f"h3: {cert['h3']}",
        "",
        f"Compliance Timestamp: {cert['compliance_timestamp']}",
        f"Compliance Status: {cert['compliance_status']}",
        f"Generated At: {cert['generate_time']}",
    ]
    content = ["BT", "/F1 10 Tf", "50 820 Td"]
    y = 820
    for idx, line in enumerate(lines):
        safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if idx == 0:
            content.append(f"({safe}) Tj")
        else:
            content.append("0 -16 Td")
            content.append(f"({safe}) Tj")
        y -= 16
        if y < 40:
            break
    content.append("ET")
    stream_data = "\n".join(content).encode("latin-1", errors="replace")

    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n",
        b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
        b"5 0 obj << /Length " + str(len(stream_data)).encode("ascii") + b" >> stream\n" + stream_data + b"\nendstream endobj\n",
    ]

    pdf = b"%PDF-1.4\n"
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf += obj
    xref_pos = len(pdf)
    pdf += b"xref\n0 6\n0000000000 65535 f \n"
    for i in range(1, 6):
        pdf += f"{offsets[i]:010d} 00000 n \n".encode("ascii")
    pdf += b"trailer << /Size 6 /Root 1 0 R >>\nstartxref\n"
    pdf += str(xref_pos).encode("ascii") + b"\n%%EOF"
    return pdf


def step_1_prepare_data():
    st.subheader("Step 1 · 数据准备")
    uploaded_file = st.file_uploader("📤 上传车源数据（Excel）", type=["xlsx", "xls"])
    c1, c2 = st.columns([1, 1])

    with c1:
        if st.button("🧪 使用内嵌示例数据", use_container_width=True):
            st.session_state.raw_df = load_embedded_default_df()
            st.session_state.uploaded_signature = "embedded_default"
            reset_pipeline_state()
            st.success("已加载内嵌示例数据。")

    with c2:
        sample_excel = get_embedded_default_excel_bytes()
        if sample_excel is not None:
            st.download_button(
                "📥 下载示例Excel",
                data=sample_excel,
                file_name="成都出口车源模拟数据.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
            )
        else:
            st.button("📥 下载示例Excel", disabled=True, use_container_width=True)

    if uploaded_file is not None:
        signature = f"{uploaded_file.name}_{uploaded_file.size}"
        if st.session_state.uploaded_signature != signature:
            df, err = try_load_excel(uploaded_file)
            if err is None:
                st.session_state.raw_df = df
                st.session_state.uploaded_signature = signature
                reset_pipeline_state()
                st.success("文件上传成功。")
            else:
                st.error(f"Excel读取失败：{err}")

    go_next_if_allowed(st.session_state.raw_df is not None)


def step_2_preview_raw():
    st.subheader("Step 2 · 原始数据预览")
    if st.session_state.raw_df is None:
        st.warning("请先完成 Step 1。")
        return
    st.dataframe(st.session_state.raw_df.head(8), use_container_width=True)
    go_next_if_allowed(True)


def step_3_desensitize():
    st.subheader("Step 3 · 数据脱敏")
    if st.session_state.raw_df is None:
        st.warning("请先完成 Step 1。")
        return
    if st.button("🛡️ 执行数据脱敏", use_container_width=True):
        st.session_state.masked_df = desensitize_data(st.session_state.raw_df)
        st.session_state.hashed_df = None
        try:
            st.session_state.masked_df.to_excel("脱敏后_成都出口车源数据.xlsx", index=False)
        except Exception:
            pass
        st.success("脱敏完成。")
    if st.session_state.masked_df is not None:
        st.dataframe(st.session_state.masked_df, use_container_width=True)
    go_next_if_allowed(st.session_state.masked_df is not None)


def step_4_hash_chain():
    st.subheader("Step 4 · 哈希链存证")
    if st.session_state.masked_df is None:
        st.warning("请先完成 Step 3。")
        return
    if st.button("⛓️ 生成哈希链（模拟上链）", use_container_width=True):
        st.session_state.hashed_df = build_hash_chain(st.session_state.masked_df)
        try:
            st.session_state.hashed_df.to_excel("哈希链存证记录.xlsx", index=False)
        except Exception:
            pass
        st.success("哈希链生成完成。")
    if st.session_state.hashed_df is not None:
        st.dataframe(st.session_state.hashed_df, use_container_width=True)
    go_next_if_allowed(st.session_state.hashed_df is not None)


def step_5_verify():
    st.subheader("Step 5 · VIN篡改验证")
    if st.session_state.hashed_df is None:
        st.warning("请先完成 Step 4。")
        return
    if st.session_state.masked_df is not None:
        st.dataframe(st.session_state.masked_df.head(5), use_container_width=True)
        st.markdown(
            '<div style="color: rgba(107,114,128,0.78); font-size: 12px; margin-top: 4px;">可以在下列示例表格第一列随意复制一个VIN码进行篡改验证</div>',
            unsafe_allow_html=True,
        )
    vin_input = st.text_input("🔎 请输入 VIN 码进行验证")
    if st.button("✅ 执行篡改验证", use_container_width=True):
        message = verify_by_vin(st.session_state.hashed_df, vin_input)
        show_verify_dialog(message)
    go_next_if_allowed(True)


def step_6_certificate():
    st.subheader("Step 6 · 生成可信证书")
    if st.session_state.hashed_df is None:
        st.warning("请先完成 Step 4。")
        return
    vin_input = st.text_input("🔎 请输入 VIN 码查询证书")
    row = find_row_by_vin(st.session_state.hashed_df, vin_input)
    if row is None:
        return
    cert = build_certificate_dict(row)
    render_certificate_preview(cert)
    pdf_bytes = generate_pdf_bytes(cert)
    st.download_button(
        "点击下载 PDF 证书",
        data=pdf_bytes,
        file_name=f"二手车跨境数据可信存证证书_{cert['vin_code']}.pdf",
        mime="application/pdf",
        type="primary",
        use_container_width=True,
    )


def main():
    st.set_page_config(page_title="跨境二手车数据合规网关", layout="wide")
    init_session_state()
    render_sidebar()
    st.title("跨境二手车数据合规网关")

    current = st.session_state.current_step
    if current == 0:
        step_1_prepare_data()
    elif current == 1:
        step_2_preview_raw()
    elif current == 2:
        step_3_desensitize()
    elif current == 3:
        step_4_hash_chain()
    elif current == 4:
        step_5_verify()
    elif current == 5:
        step_6_certificate()


if __name__ == "__main__":
    main()
