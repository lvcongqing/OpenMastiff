import { useI18n } from "../i18n/LocaleContext";

type Props = {
  size?: number;
  vertical?: boolean;
  subtitle?: string;
};

export default function BrandMark({ size = 40, vertical = false, subtitle }: Props) {
  const { t } = useI18n();
  const text = subtitle === undefined ? t("brand.subtitle") : subtitle;
  return (
    <div className={`brand-mark${vertical ? " is-vertical" : ""}`}>
      <img src="/logo.png" alt="OpenMastiff" width={size} height={size} className="brand-mark-logo" />
      <div className="brand-mark-text">
        <div className="brand-mark-title">OpenMastiff</div>
        {text ? <div className="brand-mark-sub">{text}</div> : null}
      </div>
    </div>
  );
}
