import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class WxapkgApiTestMain {
    @Test
    public void normalizesOpenAiCompatibleBaseUrlsToChatCompletions() {
        assertEquals(
                "https://api.minimax.io/v1/chat/completions",
                AiParamInferTab.normalizeChatCompletionsUrl("https://api.minimax.io/v1")
        );
        assertEquals(
                "https://api.minimaxi.com/v1/chat/completions",
                AiParamInferTab.normalizeChatCompletionsUrl("https://api.minimaxi.com/v1/")
        );
    }

    @Test
    public void preservesConfiguredCustomEndpoints() {
        assertEquals(
                "https://gateway.example.com/custom/chat",
                AiParamInferTab.normalizeChatCompletionsUrl("https://gateway.example.com/custom/chat")
        );
    }

    @Test
    public void exposesCurrentMinimaxPresetMetadata() {
        AiParamInferTab.ChatPreset m3Global = AiParamInferTab.getPreset("MiniMax / MiniMax-M3 (Global)");
        AiParamInferTab.ChatPreset m27China = AiParamInferTab.getPreset("MiniMax / MiniMax-M2.7 (China)");

        assertNotNull(m3Global);
        assertNotNull(m27China);
        assertEquals("MiniMax", m3Global.providerName());
        assertEquals("MiniMax-M3", m3Global.modelName());
        assertEquals("https://api.minimax.io/v1", m3Global.modelUrl());
        assertEquals("1000000", m3Global.contextLength());
        assertEquals("MiniMax-M2.7", m27China.modelName());
        assertEquals("https://api.minimaxi.com/v1", m27China.modelUrl());
        assertEquals("204800", m27China.contextLength());
    }
}
