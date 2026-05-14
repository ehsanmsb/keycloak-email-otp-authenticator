<#ftl output_format="plainText">
<#if emailIntroText?? && emailIntroText?has_content>
${emailIntroText}

</#if>
${msg("emailCodeBody", code, ttl)}
